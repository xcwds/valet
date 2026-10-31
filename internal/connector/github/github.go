// Package github is the GitHub connector (RFC GitHub connector, decision 9).
//
// It authenticates as one GitHub App and mints an installation token per job,
// narrowed to exactly the job's repositories and to the permissions
// configured for the job's role. Tokens are carried as secrets.Secret, never
// logged or returned, and revoked upstream when the job ends. The action
// catalog arrives with #13.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/jobs"
	"github.com/xcwds/valet/internal/secrets"
)

// Name is the connector's namespace.
const Name = "github"

// Backoff bounds for failed mints.
const (
	minBackoff = time.Second
	maxBackoff = 5 * time.Minute
)

// SecretGetter reads the App's private key from the secret store.
type SecretGetter interface {
	Get(ctx context.Context, name string) (secrets.Secret, error)
}

// Connector is the GitHub connector.
type Connector struct {
	cfg     Config
	secrets SecretGetter
	http    *http.Client
	now     func() time.Time

	mu        sync.Mutex
	owner     string // the installation's account login, lowercased
	notBefore time.Time
	failures  map[string]failure // per job
}

type failure struct {
	n     int
	until time.Time
	err   error
}

// installation is what a minted credential's Data holds.
type installation struct{ ID int64 }

// New returns a GitHub connector. cfg is validated (and defaulted) here.
func New(cfg Config, s SecretGetter) (*Connector, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Connector{
		cfg:     cfg,
		secrets: s,
		http: &http.Client{
			Timeout: 20 * time.Second,
			// Never follow a redirect with a JWT or token attached.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now:      time.Now,
		failures: map[string]failure{},
	}, nil
}

// Name implements connector.Connector.
func (*Connector) Name() string { return Name }

// Mint implements connector.Connector: an installation token for exactly the
// job's repositories, with the job's role's permissions.
func (c *Connector) Mint(ctx context.Context, job jobs.Job) (connector.Credential, error) {
	perms, ok := c.cfg.Permissions[job.Role]
	if !ok {
		return connector.Credential{}, fmt.Errorf("github: role %q has no GitHub permissions configured", job.Role)
	}
	repos := job.Repos()
	if len(repos) == 0 {
		// An empty list would mean every repository the installation can
		// see.
		return connector.Credential{}, errors.New("github: the job has no repositories")
	}
	if err := c.checkBackoff(job.ID); err != nil {
		return connector.Credential{}, err
	}
	cred, err := c.mint(ctx, repos, perms)
	c.recordResult(job.ID, err)
	return cred, err
}

func (c *Connector) checkBackoff(jobID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if now.Before(c.notBefore) {
		return fmt.Errorf("github: rate limited until %s", c.notBefore.UTC().Format(time.RFC3339))
	}
	if f, ok := c.failures[jobID]; ok && now.Before(f.until) {
		return fmt.Errorf("github: retrying after %s: %w", f.until.UTC().Format(time.RFC3339), f.err)
	}
	return nil
}

func (c *Connector) recordResult(jobID string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		delete(c.failures, jobID)
		return
	}
	f := c.failures[jobID]
	f.n++
	wait := minBackoff << min(f.n-1, 16)
	f.until, f.err = c.now().Add(min(wait, maxBackoff)), err
	c.failures[jobID] = f
	// Bound memory: forget failures that are long past.
	if len(c.failures) > 1000 {
		for id, old := range c.failures {
			if c.now().Sub(old.until) > maxBackoff {
				delete(c.failures, id)
			}
		}
	}
}

func (c *Connector) mint(ctx context.Context, repos []string, perms map[string]string) (connector.Credential, error) {
	keySecret, err := c.secrets.Get(ctx, c.cfg.PrivateKeySecret)
	if err != nil {
		return connector.Credential{}, fmt.Errorf("github: App key %q: %w", c.cfg.PrivateKeySecret, err)
	}
	key, err := parseKey(keySecret.Reveal())
	if err != nil {
		return connector.Credential{}, fmt.Errorf("github: App key %q: %w", c.cfg.PrivateKeySecret, err)
	}
	jwt, err := appJWT(key, c.cfg.AppID, c.now())
	if err != nil {
		return connector.Credential{}, fmt.Errorf("github: signing the App JWT: %w", err)
	}

	owner, err := c.installationOwner(ctx, jwt)
	if err != nil {
		return connector.Credential{}, err
	}
	// The API takes bare repository names, scoped to the installation's
	// account. A job repo under another owner must not quietly become the
	// installation's repo of the same name.
	names := make([]string, 0, len(repos))
	for _, r := range repos {
		o, n, _ := strings.Cut(r, "/")
		if !strings.EqualFold(o, owner) {
			return connector.Credential{}, fmt.Errorf("github: %s is not in the installation's account (%s)", r, owner)
		}
		names = append(names, n)
	}

	body, _ := json.Marshal(map[string]any{"repositories": names, "permissions": perms})
	var resp struct {
		Token        string            `json:"token"`
		ExpiresAt    time.Time         `json:"expires_at"`
		Permissions  map[string]string `json:"permissions"`
		Selection    string            `json:"repository_selection"`
		Repositories []struct {
			FullName string `json:"full_name"`
		} `json:"repositories"`
	}
	path := fmt.Sprintf("/app/installations/%d/access_tokens", c.cfg.InstallationID)
	if err := c.call(ctx, http.MethodPost, path, "Bearer "+jwt, body, http.StatusCreated, &resp); err != nil {
		return connector.Credential{}, err
	}
	cred := connector.Credential{
		Secret:    secrets.NewSecret([]byte(resp.Token)),
		ExpiresAt: resp.ExpiresAt,
		Data:      installation{ID: c.cfg.InstallationID},
	}
	if resp.Token == "" || resp.ExpiresAt.IsZero() {
		return connector.Credential{}, errors.New("github: access token response is missing the token or its expiry")
	}
	// Belt and braces: never use a token broader than asked for.
	if err := checkGrant(resp.Permissions, perms, resp.Selection, resp.Repositories, repos); err != nil {
		_ = c.Revoke(context.WithoutCancel(ctx), cred)
		return connector.Credential{}, err
	}
	return cred, nil
}

func checkGrant(got, want map[string]string, selection string, gotRepos []struct {
	FullName string `json:"full_name"`
}, wantRepos []string,
) error {
	// A token for every repository says "all" and lists none, so the
	// listed repositories alone can't show it's narrow.
	if selection != "selected" {
		return fmt.Errorf("github: the token covers repository selection %q, not the job's repositories; revoked", selection)
	}
	seen := map[string]bool{}
	for _, r := range gotRepos {
		seen[strings.ToLower(r.FullName)] = true
	}
	for _, r := range wantRepos {
		if !seen[r] {
			return fmt.Errorf("github: the token doesn't list %s; revoked", r)
		}
	}
	for name, level := range got {
		if name == "metadata" && level == "read" {
			continue // GitHub adds it to every installation token
		}
		asked, ok := want[name]
		if !ok || (level == "write" && asked == "read") || (level != "read" && level != "write") {
			return fmt.Errorf("github: the token has %s:%s, more than the %v asked for; revoked", name, level, want)
		}
	}
	for _, r := range gotRepos {
		if !slices.Contains(wantRepos, strings.ToLower(r.FullName)) {
			return fmt.Errorf("github: the token covers %s, which the job wasn't granted; revoked", r.FullName)
		}
	}
	return nil
}

// installationOwner returns (and caches) the account the installation
// belongs to.
func (c *Connector) installationOwner(ctx context.Context, jwt string) (string, error) {
	c.mu.Lock()
	owner := c.owner
	c.mu.Unlock()
	if owner != "" {
		return owner, nil
	}
	var resp struct {
		Account struct {
			Login string `json:"login"`
		} `json:"account"`
	}
	path := fmt.Sprintf("/app/installations/%d", c.cfg.InstallationID)
	if err := c.call(ctx, http.MethodGet, path, "Bearer "+jwt, nil, http.StatusOK, &resp); err != nil {
		return "", err
	}
	if resp.Account.Login == "" {
		return "", errors.New("github: installation has no account login")
	}
	owner = strings.ToLower(resp.Account.Login)
	c.mu.Lock()
	c.owner = owner
	c.mu.Unlock()
	return owner, nil
}

// Revoke implements connector.Revoker: the token stops working before it
// expires. An already expired or revoked token counts as revoked.
func (c *Connector) Revoke(ctx context.Context, cred connector.Credential) error {
	err := c.call(ctx, http.MethodDelete, "/installation/token", "Bearer "+string(cred.Secret.Reveal()), nil, http.StatusNoContent, nil)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
		return nil
	}
	return err
}

// APIError is a non-success answer from GitHub.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("github: HTTP %d: %s", e.Status, e.Message) }

func (c *Connector) call(ctx context.Context, method, path, auth string, body []byte, want int, out any) error {
	status, data, _, err := c.send(ctx, method, path, auth, "application/vnd.github+json", body, 1<<20)
	if err != nil {
		return err
	}
	if status != want {
		return apiError(status, data)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("github: %s %s: %w", method, path, err)
		}
	}
	return nil
}

func apiError(status int, data []byte) *APIError {
	var e struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(data, &e)
	if e.Message == "" {
		e.Message = http.StatusText(status)
	}
	return &APIError{Status: status, Message: e.Message}
}

// send makes one request and returns the status and up to limit bytes of
// the body; truncated reports whether there was more.
func (c *Connector) send(ctx context.Context, method, path, auth, accept string, body []byte, limit int64) (status int, data []byte, truncated bool, err error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.APIURL+path, rd)
	if err != nil {
		return 0, nil, false, err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "valet")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, false, fmt.Errorf("github: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ = io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if int64(len(data)) > limit {
		data, truncated = data[:limit], true
	}
	c.noteRateLimit(resp)
	return resp.StatusCode, data, truncated, nil
}

// noteRateLimit pauses every mint when GitHub says to: Retry-After on a 403
// or 429, or an exhausted rate limit with its reset time.
func (c *Connector) noteRateLimit(resp *http.Response) {
	var until time.Time
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden {
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			until = c.now().Add(time.Duration(s) * time.Second)
		}
	}
	if resp.Header.Get("X-RateLimit-Remaining") == "0" {
		if reset, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			until = time.Unix(reset, 0)
		}
	}
	if until.IsZero() {
		return
	}
	if until.After(c.now().Add(time.Hour)) {
		until = c.now().Add(time.Hour) // never trust a reset far in the future
	}
	c.mu.Lock()
	if until.After(c.notBefore) {
		c.notBefore = until
	}
	c.mu.Unlock()
}
