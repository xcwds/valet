package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/xcwds/valet/internal/alert"
	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/throttle"
	"github.com/xcwds/valet/internal/tokens"
)

// Enrollment (RFC decision 10, the Enrollment section): a container
// exchanges a one-time code, created with its job on the admin port, for
// the job's one session. A short repeat window answers a retried first use
// with exactly the same response, so a response lost in transit isn't a
// false alarm; anything else that reuses a code is denied and alerted.

// Enrollment limits.
const (
	DefaultCodeTTL      = 10 * time.Minute
	MaxCodeTTL          = 24 * time.Hour
	DefaultReplayWindow = 60 * time.Second
	MaxReplayWindow     = 5 * time.Minute
	DefaultMaxReplays   = 5
	MaxMaxReplays       = 20
)

// ErrEnrollRefused is the one answer to a refused code: the caller learns
// nothing about why. The audit record carries the reason.
var ErrEnrollRefused = errors.New("enrollment refused")

// EnrollConfig tunes enrollment (config enrollment:).
type EnrollConfig struct {
	CodeTTL      time.Duration // how long a code stays usable for first use
	ReplayWindow time.Duration // how long after first use a retry gets the same answer
	MaxReplays   int           // how many retries a code gets within the window
}

// DefaultEnrollConfig is 10 minutes, 60 seconds and 5 replays.
func DefaultEnrollConfig() EnrollConfig {
	return EnrollConfig{CodeTTL: DefaultCodeTTL, ReplayWindow: DefaultReplayWindow, MaxReplays: DefaultMaxReplays}
}

// Validate checks the bounds.
func (c EnrollConfig) Validate() error {
	var errs []error
	if c.CodeTTL < MinTTL || c.CodeTTL > MaxCodeTTL {
		errs = append(errs, fmt.Errorf("code_ttl %s: must be between %s and %s", c.CodeTTL, MinTTL, MaxCodeTTL))
	}
	if c.ReplayWindow < 0 || c.ReplayWindow > MaxReplayWindow {
		errs = append(errs, fmt.Errorf("replay_window %s: must be between 0 and %s", c.ReplayWindow, MaxReplayWindow))
	}
	if c.MaxReplays < 0 || c.MaxReplays > MaxMaxReplays {
		errs = append(errs, fmt.Errorf("max_replays %d: must be between 0 and %d", c.MaxReplays, MaxMaxReplays))
	}
	return errors.Join(errs...)
}

// SetEnrollConfig replaces the defaults. Call before serving.
func (s *Service) SetEnrollConfig(c EnrollConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	s.enroll = c
	return nil
}

// Alerter receives refused enrollments (alert.Dispatcher).
type Alerter interface{ Send(alert.Alert) }

// SetAlerter sends refused enrollments to a. Set it before serving.
func (s *Service) SetAlerter(a Alerter) { s.alerts = a }

// Enrollment is an issued one-time code.
type Enrollment struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

// EnrollResponse is what a code is exchanged for.
type EnrollResponse struct {
	SessionToken string    `json:"session_token"`
	JobID        string    `json:"job_id"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// replay is a first use's response, kept in memory (never stored) for the
// repeat window.
type replay struct {
	jobID  string
	body   []byte
	until  time.Time
	served int
	timer  *time.Timer
}

// CreateForEnrollment stores a job with no session yet and returns a
// one-time code for it; the container exchanges the code at start-up.
func (s *Service) CreateForEnrollment(ctx context.Context, req CreateRequest) (Job, Enrollment, error) {
	var e Enrollment
	job, err := s.create(ctx, req, func(tx *sql.Tx, job Job, now time.Time) (map[string]any, string, error) {
		var params map[string]any
		var err error
		e, params, err = s.insertCode(ctx, tx, job.ID, now)
		return params, "", err
	})
	if err != nil {
		return Job{}, Enrollment{}, err
	}
	return job, e, nil
}

func (s *Service) insertCode(ctx context.Context, tx *sql.Tx, jobID string, now time.Time) (Enrollment, map[string]any, error) {
	id, err := newID("enr-")
	if err != nil {
		return Enrollment{}, nil, err
	}
	code, hash, err := tokens.New(tokens.Enroll)
	if err != nil {
		return Enrollment{}, nil, err
	}
	exp := now.Add(s.enroll.CodeTTL)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO enrollments (id, job_id, code_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		id, jobID, hash, ts(now), ts(exp)); err != nil {
		return Enrollment{}, nil, fmt.Errorf("jobs: create enrollment: %w", err)
	}
	return Enrollment{Code: code, ExpiresAt: exp}, map[string]any{"enrollment": id, "code_expires_at": ts(exp)}, nil
}

// Reenroll gives an active job a fresh code, revoking its session and any
// unused code: the only way a job gets a second session.
func (s *Service) Reenroll(ctx context.Context, id, by string) (Enrollment, error) {
	if !ValidID(id) {
		return Enrollment{}, fmt.Errorf("jobs: %q: %w", id, ErrNotFound)
	}
	var e Enrollment
	var rec audit.Record
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		job, err := s.scanJob(tx.QueryRowContext(ctx, selectJobs+` WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("jobs: %s: %w", id, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if job.State != StateActive {
			return fmt.Errorf("jobs: %s is %s: %w", id, job.State, ErrNotActive)
		}
		now := s.now().UTC()
		res, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE job_id = ? AND revoked_at IS NULL`, ts(now), id)
		if err != nil {
			return fmt.Errorf("jobs: re-enroll: %w", err)
		}
		sessions, _ := res.RowsAffected()
		if _, err := tx.ExecContext(ctx, `UPDATE enrollments SET revoked_at = ? WHERE job_id = ? AND revoked_at IS NULL`, ts(now), id); err != nil {
			return fmt.Errorf("jobs: re-enroll: %w", err)
		}
		var params map[string]any
		if e, params, err = s.insertCode(ctx, tx, id, now); err != nil {
			return err
		}
		params["by"], params["sessions_revoked"] = by, sessions
		rec, err = s.audit.AppendTx(ctx, tx, audit.Event{
			JobID: id, Interface: audit.InterfaceAdmin, Action: "job.enroll", Decision: audit.Allow, Params: params,
		})
		return err
	})
	if err != nil {
		return Enrollment{}, err
	}
	s.audit.Emit(ctx, rec)
	s.dropReplays(id)
	for _, f := range s.onSessionsRevoked {
		f(context.WithoutCancel(ctx), id)
	}
	return e, nil
}

// OnSessionsRevoked registers f to run when a job's sessions are revoked
// but the job goes on (re-enrollment), e.g. to close what the old session
// opened.
func (s *Service) OnSessionsRevoked(f func(ctx context.Context, jobID string)) {
	s.onSessionsRevoked = append(s.onSessionsRevoked, f)
}

// Enroll exchanges a code for the job's session and returns the exact
// response body. First use creates the session; within the repeat window
// the same code gets the same bytes back. Anything else is
// ErrEnrollRefused (audited and alerted) or ErrThrottled.
func (s *Service) Enroll(ctx context.Context, code, source string) ([]byte, error) {
	hash, err := tokens.Parse(tokens.Enroll, code)
	if err != nil {
		return nil, s.enrollRefused(ctx, source, "", "malformed code")
	}
	var (
		body          []byte
		reason, jobID string
		putReplay     string // an entry this call added, removed if the write fails
		rec           audit.Record
	)
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		var enrID, expires string
		var used, revoked sql.NullString
		err := tx.QueryRowContext(ctx,
			`SELECT id, job_id, expires_at, used_at, revoked_at FROM enrollments WHERE code_hash = ?`, hash).
			Scan(&enrID, &jobID, &expires, &used, &revoked)
		if errors.Is(err, sql.ErrNoRows) {
			reason = "unknown code"
			return nil
		}
		if err != nil {
			return fmt.Errorf("jobs: enroll: %w", err)
		}
		job, err := s.scanJob(tx.QueryRowContext(ctx, selectJobs+` WHERE id = ?`, jobID))
		if err != nil {
			return err
		}
		now := s.now().UTC()
		switch {
		case job.State != StateActive:
			reason = "job " + job.State
		case revoked.Valid:
			reason = "code superseded by a re-enrollment"
		case used.Valid:
			var served int
			body, served, reason = s.takeReplay(enrID, now)
			if reason != "" {
				return nil
			}
			rec, err = s.audit.AppendTx(ctx, tx, audit.Event{
				JobID: jobID, Interface: audit.InterfaceEnroll, Action: "session.enroll", Decision: audit.Allow,
				Params: map[string]any{"enrollment": enrID, "replay": true, "replays": served, "source": source},
			})
			return err
		default:
			exp, err := time.Parse(time.RFC3339Nano, expires)
			if err != nil {
				return fmt.Errorf("jobs: enrollment %s: expires_at: %w", enrID, err)
			}
			if !now.Before(exp) {
				reason = "code expired"
				return nil
			}
			sessionID, err := newID("ses-")
			if err != nil {
				return err
			}
			token, thash, err := tokens.New(tokens.Session)
			if err != nil {
				return err
			}
			// Conditional: exactly one first use, even if writes ever
			// stopped being serialized.
			res, err := tx.ExecContext(ctx,
				`UPDATE enrollments SET used_at = ?, session_id = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL`,
				ts(now), sessionID, enrID)
			if err != nil {
				return fmt.Errorf("jobs: enroll: %w", err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				reason = "code already used"
				return nil
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO sessions (id, job_id, token_hash, created_at) VALUES (?, ?, ?, ?)`,
				sessionID, jobID, thash, ts(now)); err != nil {
				return fmt.Errorf("jobs: enroll: create session: %w", err)
			}
			// The session token is this response's purpose (decision 17).
			resp := EnrollResponse{SessionToken: token, JobID: jobID, ExpiresAt: job.ExpiresAt}
			if body, err = json.Marshal(resp); err != nil { //nolint:gosec // G117: returning the token is the point
				return err
			}
			// Kept before commit, so a racing retry that sees used_at
			// also finds the response.
			s.putReplay(enrID, jobID, body, now)
			putReplay = enrID
			rec, err = s.audit.AppendTx(ctx, tx, audit.Event{
				JobID: jobID, SessionID: sessionID, Interface: audit.InterfaceEnroll, Action: "session.enroll", Decision: audit.Allow,
				Params: map[string]any{"enrollment": enrID, "source": source},
			})
			return err
		}
		return nil
	})
	if err != nil {
		if putReplay != "" {
			s.dropReplay(putReplay)
		}
		return nil, err
	}
	if reason != "" {
		return nil, s.enrollRefused(ctx, source, jobID, reason)
	}
	s.audit.Emit(ctx, rec)
	return body, nil
}

// enrollRefused audits and alerts a refused code, within the per-source
// throttle shared with session authentication.
func (s *Service) enrollRefused(ctx context.Context, source, jobID, reason string) error {
	params := map[string]any{"reason": reason, "source": source}
	result := ErrEnrollRefused
	switch s.throttle.Failure(source) {
	case throttle.Suppress:
		return ErrThrottled
	case throttle.RecordLimit:
		params["reason"] = "throttled: too many failed authentications"
		result = ErrThrottled
	}
	rec, err := s.audit.Append(ctx, audit.Event{
		JobID: jobID, Interface: audit.InterfaceEnroll, Action: "session.enroll", Decision: audit.Deny,
		Rule: "enroll/refused", Error: reason, Params: params,
	})
	if err != nil {
		return errors.Join(result, err)
	}
	if s.alerts != nil {
		s.alerts.Send(alert.Alert{
			JobID: rec.JobID, Action: rec.Action, Decision: rec.Decision, Rule: rec.Rule,
			Reason: reason, Params: rec.Params, AuditSeq: rec.Seq, RuleAlert: true,
		})
	}
	return result
}

func (s *Service) putReplay(enrID, jobID string, body []byte, now time.Time) {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	r := &replay{jobID: jobID, body: body, until: now.Add(s.enroll.ReplayWindow)}
	r.timer = time.AfterFunc(s.enroll.ReplayWindow, func() { s.dropReplay(enrID) })
	s.replays[enrID] = r
}

// takeReplay returns the first use's response for a retry, or why not.
func (s *Service) takeReplay(enrID string, now time.Time) ([]byte, int, string) {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	r, ok := s.replays[enrID]
	switch {
	case !ok:
		return nil, 0, "code already used"
	case !now.Before(r.until):
		return nil, 0, "code already used (repeat window over)"
	case r.served >= s.enroll.MaxReplays:
		return nil, 0, "code already used (replay limit reached)"
	}
	r.served++
	return r.body, r.served, ""
}

// dropReplay forgets a response and wipes the token from memory.
func (s *Service) dropReplay(enrID string) {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	if r, ok := s.replays[enrID]; ok {
		r.timer.Stop()
		clear(r.body)
		delete(s.replays, enrID)
	}
}

// dropReplays forgets every response for a job (revoked or re-enrolled).
func (s *Service) dropReplays(jobID string) {
	s.replayMu.Lock()
	var ids []string
	for id, r := range s.replays {
		if r.jobID == jobID {
			ids = append(ids, id)
		}
	}
	s.replayMu.Unlock()
	for _, id := range ids {
		s.dropReplay(id)
	}
}
