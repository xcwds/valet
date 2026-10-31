// Package jobs manages jobs and their session tokens.
//
// A job is one unit of agent work: a role bound to concrete resources, with a
// TTL (RFC Core concepts). Its session token is the only secret an agent
// holds (decision 1). Tokens are stored only as SHA-256 hashes; a session is
// valid only while its job is active and unexpired, checked on every request
// (decision 11: TTL and revocation, no IP binding).
package jobs

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/store"
	"github.com/xcwds/valet/internal/throttle"
	"github.com/xcwds/valet/internal/tokens"
)

// TTL bounds.
const (
	DefaultTTL = time.Hour
	MinTTL     = time.Minute
	MaxTTL     = 24 * time.Hour
	MaxRepos   = 20
)

// Job states. "expired" is derived from expires_at, not stored.
const (
	StateActive  = "active"
	StateExpired = "expired"
	StateRevoked = "revoked"
)

var (
	// ErrNotFound is returned for an unknown job.
	ErrNotFound = errors.New("job not found")
	// ErrInvalid wraps every validation failure in a CreateRequest.
	ErrInvalid = errors.New("invalid job")
	// ErrNotActive is returned when revoking a job that is already revoked.
	ErrNotActive = errors.New("job is not active")
	// ErrUnauthenticated covers every way a session token can fail. Callers
	// see one error, so a probe learns nothing about which part was wrong;
	// the audit record carries the reason.
	ErrUnauthenticated = errors.New("unauthenticated")
	// ErrThrottled is returned once a source has failed too often; those
	// failures are no longer audited one by one.
	ErrThrottled = errors.New("too many failed authentications")

	roleName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	jobIDRe  = regexp.MustCompile(`^job-[a-z2-7]{8}$`)
	repoName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}/[a-z0-9._-]{1,100}$`)
)

// Grants are the concrete resources a job may touch, per connector.
type Grants struct {
	GitHub *GitHubGrant `json:"github,omitempty"`
}

// GitHubGrant lists the repositories a job may use.
type GitHubGrant struct {
	Repos []string `json:"repos"`
}

// Job is a stored job.
type Job struct {
	ID            string    `json:"id"`
	Role          string    `json:"role"`
	Grants        Grants    `json:"grants"`
	BranchPattern string    `json:"branch_pattern"`
	TTL           string    `json:"ttl"`
	ExpiresAt     time.Time `json:"expires_at"`
	State         string    `json:"state"` // effective: active, expired or revoked
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
	RevokedAt     time.Time `json:"revoked_at,omitzero"`
}

// Repos returns the job's GitHub repositories, if any.
func (j Job) Repos() []string {
	if j.Grants.GitHub == nil {
		return nil
	}
	return j.Grants.GitHub.Repos
}

// Service creates, reads and revokes jobs and authenticates sessions.
type Service struct {
	db       *store.Store
	audit    *audit.Log
	throttle *throttle.Throttle
	now      func() time.Time
	onRevoke []func(ctx context.Context, jobID string)
}

// OnRevoke registers f to run after a job is revoked, e.g. to drop and revoke
// its upstream credentials. Register before serving requests.
func (s *Service) OnRevoke(f func(ctx context.Context, jobID string)) {
	s.onRevoke = append(s.onRevoke, f)
}

// NewService returns a Service.
func NewService(db *store.Store, log *audit.Log) *Service {
	return &Service{db: db, audit: log, throttle: throttle.New(throttle.DefaultLimit, throttle.DefaultWindow), now: time.Now}
}

// CreateRequest describes a new job.
type CreateRequest struct {
	Role      string        `json:"role"`
	Repos     []string      `json:"repos"`
	TTL       time.Duration `json:"-"`
	CreatedBy string        `json:"-"`
}

// NormalizeRepo validates and lowercases an owner/name repository.
func NormalizeRepo(r string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(r))
	if !repoName.MatchString(n) || strings.Contains(n, "..") || strings.HasSuffix(n, ".git") {
		return "", fmt.Errorf("%w: repository %q: want owner/name", ErrInvalid, r)
	}
	return n, nil
}

func (req CreateRequest) validate() (CreateRequest, error) {
	if !roleName.MatchString(req.Role) {
		return req, fmt.Errorf("%w: role %q: want lowercase letters, digits and -", ErrInvalid, req.Role)
	}
	if req.TTL == 0 {
		req.TTL = DefaultTTL
	}
	if req.TTL < MinTTL || req.TTL > MaxTTL {
		return req, fmt.Errorf("%w: ttl %s: must be between %s and %s", ErrInvalid, req.TTL, MinTTL, MaxTTL)
	}
	if len(req.Repos) > MaxRepos {
		return req, fmt.Errorf("%w: %d repositories: at most %d", ErrInvalid, len(req.Repos), MaxRepos)
	}
	var repos []string
	for _, r := range req.Repos {
		n, err := NormalizeRepo(r)
		if err != nil {
			return req, err
		}
		if !slices.Contains(repos, n) {
			repos = append(repos, n)
		}
	}
	req.Repos = repos
	if req.CreatedBy == "" {
		return req, fmt.Errorf("%w: created_by is required", ErrInvalid)
	}
	return req, nil
}

// newJobID is "job-" and 8 base32 characters: short enough for branch names
// (agent/job-k3x9q2ma/fix), random enough not to guess.
func newJobID() (string, error) {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "job-" + strings.ToLower(base32.StdEncoding.EncodeToString(b)), nil
}

func newID(prefix string) (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + strings.ToLower(base32.StdEncoding.EncodeToString(b)), nil
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// Create stores a job and its session and returns the session token, which is
// never stored or shown again. The job, the session and the audit record
// commit together.
func (s *Service) Create(ctx context.Context, req CreateRequest) (Job, string, error) {
	req, err := req.validate()
	if err != nil {
		return Job{}, "", err
	}
	id, err := newJobID()
	if err != nil {
		return Job{}, "", err
	}
	sessionID, err := newID("ses-")
	if err != nil {
		return Job{}, "", err
	}
	token, hash, err := tokens.New(tokens.Session)
	if err != nil {
		return Job{}, "", err
	}
	now := s.now().UTC()
	job := Job{
		ID:            id,
		Role:          req.Role,
		BranchPattern: "agent/" + id + "/*",
		TTL:           req.TTL.String(),
		ExpiresAt:     now.Add(req.TTL),
		State:         StateActive,
		CreatedBy:     req.CreatedBy,
		CreatedAt:     now,
	}
	if len(req.Repos) > 0 {
		job.Grants.GitHub = &GitHubGrant{Repos: req.Repos}
	}
	grants, err := json.Marshal(job.Grants)
	if err != nil {
		return Job{}, "", err
	}

	var rec audit.Record
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO jobs (id, role, grants, branch_pattern, ttl_seconds, expires_at, state, created_by, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			job.ID, job.Role, string(grants), job.BranchPattern, int64(req.TTL/time.Second),
			ts(job.ExpiresAt), StateActive, job.CreatedBy, ts(now)); err != nil {
			return fmt.Errorf("jobs: create: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO sessions (id, job_id, token_hash, created_at) VALUES (?, ?, ?, ?)`,
			sessionID, job.ID, hash, ts(now)); err != nil {
			return fmt.Errorf("jobs: create session: %w", err)
		}
		rec, err = s.audit.AppendTx(ctx, tx, audit.Event{
			JobID: job.ID, SessionID: sessionID, Interface: audit.InterfaceAdmin,
			Action: "job.create", Decision: audit.Allow,
			Params: map[string]any{
				"role": job.Role, "repos": job.Repos(), "ttl": job.TTL,
				"branch_pattern": job.BranchPattern, "created_by": job.CreatedBy,
			},
		})
		return err
	})
	if err != nil {
		return Job{}, "", err
	}
	s.audit.Emit(ctx, rec)
	return job, token, nil
}

const selectJobs = `SELECT id, role, grants, branch_pattern, ttl_seconds, expires_at, state,
	created_by, created_at, coalesce(revoked_at, '') FROM jobs`

type scanner interface{ Scan(...any) error }

func (s *Service) scanJob(row scanner) (Job, error) {
	var j Job
	var grants, expires, created, revoked string
	var ttl int64
	if err := row.Scan(&j.ID, &j.Role, &grants, &j.BranchPattern, &ttl, &expires, &j.State,
		&j.CreatedBy, &created, &revoked); err != nil {
		return Job{}, err
	}
	if err := json.Unmarshal([]byte(grants), &j.Grants); err != nil {
		return Job{}, fmt.Errorf("jobs: %s: grants: %w", j.ID, err)
	}
	j.TTL = (time.Duration(ttl) * time.Second).String()
	var err error
	if j.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires); err != nil {
		return Job{}, fmt.Errorf("jobs: %s: expires_at: %w", j.ID, err)
	}
	if j.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return Job{}, fmt.Errorf("jobs: %s: created_at: %w", j.ID, err)
	}
	if revoked != "" {
		if j.RevokedAt, err = time.Parse(time.RFC3339Nano, revoked); err != nil {
			return Job{}, fmt.Errorf("jobs: %s: revoked_at: %w", j.ID, err)
		}
	}
	if j.State == StateActive && !s.now().Before(j.ExpiresAt) {
		j.State = StateExpired
	}
	return j, nil
}

// ValidID reports whether id has the form of a job ID.
func ValidID(id string) bool { return jobIDRe.MatchString(id) }

// Get returns a job.
func (s *Service) Get(ctx context.Context, id string) (Job, error) {
	if !ValidID(id) {
		return Job{}, fmt.Errorf("jobs: %q: %w", id, ErrNotFound)
	}
	j, err := s.scanJob(s.db.Read().QueryRowContext(ctx, selectJobs+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, fmt.Errorf("jobs: %s: %w", id, ErrNotFound)
	}
	return j, err
}

// List returns jobs, newest first.
func (s *Service) List(ctx context.Context, limit int) ([]Job, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.Read().QueryContext(ctx, selectJobs+` ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("jobs: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Job
	for rows.Next() {
		j, err := s.scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// Revoke ends a job and its sessions at once. Revoking a revoked job is an
// error; revoking an expired one still records the revocation.
func (s *Service) Revoke(ctx context.Context, id, by, reason string) error {
	now := ts(s.now())
	var rec audit.Record
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE jobs SET state = ?, revoked_at = ? WHERE id = ? AND state = ?`,
			StateRevoked, now, id, StateActive)
		if err != nil {
			return fmt.Errorf("jobs: revoke: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			var state string
			err := tx.QueryRowContext(ctx, `SELECT state FROM jobs WHERE id = ?`, id).Scan(&state)
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("jobs: %s: %w", id, ErrNotFound)
			}
			return fmt.Errorf("jobs: %s is %s: %w", id, state, ErrNotActive)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE sessions SET revoked_at = ? WHERE job_id = ? AND revoked_at IS NULL`, now, id); err != nil {
			return fmt.Errorf("jobs: revoke sessions: %w", err)
		}
		rec, err = s.audit.AppendTx(ctx, tx, audit.Event{
			JobID: id, Interface: audit.InterfaceAdmin, Action: "job.revoke", Decision: audit.Allow,
			Params: map[string]any{"by": by, "reason": reason},
		})
		return err
	})
	if err != nil {
		return err
	}
	s.audit.Emit(ctx, rec)
	for _, f := range s.onRevoke {
		f(context.WithoutCancel(ctx), id)
	}
	return nil
}

// Principal is an authenticated agent session.
type Principal struct {
	SessionID string
	Job       Job
}

// Authenticate resolves a session token to its job. A failure returns
// ErrUnauthenticated and is audited with the reason and source, up to the
// throttle's limit; past it, the crossing is audited once and further
// failures from that source return ErrThrottled without a write.
func (s *Service) Authenticate(ctx context.Context, token, iface, source string) (Principal, error) {
	p, reason, err := s.authenticate(ctx, token)
	if err == nil {
		return p, nil
	}
	if reason == "" { // a database failure, not a bad token
		return Principal{}, err
	}
	params := map[string]any{"reason": reason, "source": source}
	result := ErrUnauthenticated
	switch s.throttle.Failure(source) {
	case throttle.Suppress:
		return Principal{}, ErrThrottled
	case throttle.RecordLimit:
		params["reason"] = "throttled: too many failed authentications"
		params["limit"] = fmt.Sprintf("%d per %s", throttle.DefaultLimit, throttle.DefaultWindow)
		result = ErrThrottled
	}
	if _, aerr := s.audit.Append(ctx, audit.Event{
		JobID: p.Job.ID, SessionID: p.SessionID, Interface: iface,
		Action: "session.authenticate", Decision: audit.Deny, Params: params,
	}); aerr != nil {
		return Principal{}, errors.Join(result, aerr)
	}
	return Principal{}, result
}

func (s *Service) authenticate(ctx context.Context, token string) (Principal, string, error) {
	if token == "" {
		return Principal{}, "missing token", ErrUnauthenticated
	}
	hash, err := tokens.Parse(tokens.Session, token)
	if err != nil {
		return Principal{}, "malformed token", ErrUnauthenticated
	}
	var sessionID, jobID string
	var stored []byte
	var revoked sql.NullString
	err = s.db.Read().QueryRowContext(ctx,
		`SELECT id, job_id, token_hash, revoked_at FROM sessions WHERE token_hash = ?`, hash).
		Scan(&sessionID, &jobID, &stored, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, "unknown token", ErrUnauthenticated
	}
	if err != nil {
		return Principal{}, "", fmt.Errorf("jobs: authenticate: %w", err)
	}
	if subtle.ConstantTimeCompare(stored, hash) != 1 {
		return Principal{}, "unknown token", ErrUnauthenticated
	}
	job, err := s.Get(ctx, jobID)
	if err != nil {
		return Principal{}, "", err
	}
	p := Principal{SessionID: sessionID, Job: job}
	switch {
	case revoked.Valid || job.State == StateRevoked:
		return p, "job revoked", ErrUnauthenticated
	case job.State == StateExpired:
		return p, "job expired", ErrUnauthenticated
	}
	return p, "", nil
}
