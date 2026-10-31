package github

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/jobs"
	"github.com/xcwds/valet/internal/secrets"
)

var ctx = context.Background()

var testKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

func pkcs1() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey)})
}

type secretMap map[string][]byte

func (m secretMap) Get(_ context.Context, name string) (secrets.Secret, error) {
	b, ok := m[name]
	if !ok {
		return secrets.Secret{}, secrets.ErrNotFound
	}
	return secrets.NewSecret(b), nil
}

// fakeGitHub is the slice of GitHub's API the connector uses.
type fakeGitHub struct {
	t        *testing.T
	mu       sync.Mutex
	srv      *httptest.Server
	owner    string
	requests []map[string]any // access-token request bodies
	revoked  []string
	calls    int
	n        int
	// knobs
	status     int               // force this status on access_tokens
	retryAfter string            // with it
	extraPerm  map[string]string // add to granted permissions
	extraRepo  string            // add to granted repositories
	selectAll  bool              // answer as if the token covered every repository
	dropRepos  bool              // list no repositories
	expiresIn  time.Duration
}

func newFake(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{t: t, owner: "XCWDS", expiresIn: time.Hour}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) checkJWT(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(tok, ".")
	if !ok || len(parts) != 3 {
		return false
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&testKey.PublicKey, crypto.SHA256, sum[:], sig) != nil {
		return false
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		Iss      string
		Iat, Exp int64
	}
	_ = json.Unmarshal(raw, &c)
	now := time.Now().Unix()
	return c.Iss == "12345" && c.Iat <= now && c.Exp > now && c.Exp-c.Iat <= 600
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if r.Header.Get("X-GitHub-Api-Version") == "" || r.Header.Get("Accept") != "application/vnd.github+json" {
		http.Error(w, "headers", 400)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/app/installations/42":
		if !f.checkJWT(r) {
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 42, "account": map[string]string{"login": f.owner}})
	case r.Method == "POST" && r.URL.Path == "/app/installations/42/access_tokens":
		if !f.checkJWT(r) {
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
			return
		}
		var body map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		f.requests = append(f.requests, body)
		if f.status != 0 {
			if f.retryAfter != "" {
				w.Header().Set("Retry-After", f.retryAfter)
			}
			w.WriteHeader(f.status)
			_, _ = w.Write([]byte(`{"message":"nope"}`))
			return
		}
		perms := map[string]string{"metadata": "read"}
		for k, v := range body["permissions"].(map[string]any) {
			perms[k] = v.(string)
		}
		for k, v := range f.extraPerm {
			perms[k] = v
		}
		var repos []map[string]string
		for _, n := range body["repositories"].([]any) {
			repos = append(repos, map[string]string{"full_name": f.owner + "/" + n.(string)})
		}
		if f.extraRepo != "" {
			repos = append(repos, map[string]string{"full_name": f.extraRepo})
		}
		selection := "selected"
		if f.selectAll {
			selection, repos = "all", nil
		}
		if f.dropRepos {
			repos = nil
		}
		f.n++
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": fmt.Sprintf("ghs_faketoken%d", f.n), "expires_at": time.Now().Add(f.expiresIn).UTC().Format(time.RFC3339),
			"permissions": perms, "repository_selection": selection, "repositories": repos,
		})
	case r.Method == "DELETE" && r.URL.Path == "/installation/token":
		f.revoked = append(f.revoked, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		w.WriteHeader(204)
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, 404)
	}
}

func (f *fakeGitHub) snapshot() (reqs []map[string]any, revoked []string, calls int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.requests...), append([]string(nil), f.revoked...), f.calls
}

func newConn(t *testing.T, f *fakeGitHub, mutate ...func(*Config)) *Connector {
	t.Helper()
	cfg := Config{AppID: "12345", InstallationID: 42, PrivateKeySecret: "github/app-key", APIURL: f.srv.URL}
	for _, m := range mutate {
		m(&cfg)
	}
	c, err := New(cfg, secretMap{"github/app-key": pkcs1()})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func job(id, role string, repos ...string) jobs.Job {
	return jobs.Job{ID: id, Role: role, ExpiresAt: time.Now().Add(2 * time.Hour), Grants: jobs.Grants{GitHub: &jobs.GitHubGrant{Repos: repos}}}
}

func TestMintNarrowsPerRole(t *testing.T) {
	cases := map[string]string{
		"reviewer":    `{"permissions":{"checks":"read","contents":"read","metadata":"read","pull_requests":"write"},"repositories":["site","valet"]}`,
		"implementer": `{"permissions":{"checks":"read","contents":"write","metadata":"read","pull_requests":"write"},"repositories":["site","valet"]}`,
		"triage":      `{"permissions":{"issues":"write","metadata":"read"},"repositories":["site","valet"]}`,
	}
	for role, want := range cases {
		t.Run(role, func(t *testing.T) {
			f := newFake(t)
			c := newConn(t, f)
			cred, err := c.Mint(ctx, job("job-aaaaaaaa", role, "xcwds/site", "xcwds/valet"))
			if err != nil {
				t.Fatal(err)
			}
			reqs, _, _ := f.snapshot()
			got, _ := json.Marshal(reqs[0])
			if string(got) != want {
				t.Errorf("request = %s\nwant      %s", got, want)
			}
			if !strings.HasPrefix(string(cred.Secret.Reveal()), "ghs_faketoken") || cred.ExpiresAt.IsZero() {
				t.Errorf("cred = %v, expires %s", cred.Secret, cred.ExpiresAt)
			}
		})
	}
}

func TestMintRefusals(t *testing.T) {
	cases := map[string]struct {
		job     jobs.Job
		wantErr string
	}{
		"no repositories":   {job("job-aaaaaaaa", "reviewer"), "no repositories"},
		"another owner":     {job("job-aaaaaaaa", "reviewer", "xcwds/site", "evil/site"), "not in the installation's account"},
		"unconfigured role": {job("job-aaaaaaaa", "admin", "xcwds/site"), "no GitHub permissions"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			c := newConn(t, f)
			_, err := c.Mint(ctx, tc.job)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if reqs, _, _ := f.snapshot(); len(reqs) != 0 {
				t.Errorf("an access token was requested: %v", reqs)
			}
		})
	}
}

func TestOverGrantIsRevokedAndRefused(t *testing.T) {
	for name, knob := range map[string]func(*fakeGitHub){
		"extra permission": func(f *fakeGitHub) { f.extraPerm = map[string]string{"administration": "write"} },
		"upgraded level":   func(f *fakeGitHub) { f.extraPerm = map[string]string{"contents": "write"} },
		"extra repository": func(f *fakeGitHub) { f.extraRepo = "xcwds/secrets" },
		"unknown level":    func(f *fakeGitHub) { f.extraPerm = map[string]string{"issues": "admin"} },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			knob(f)
			c := newConn(t, f)
			_, err := c.Mint(ctx, job("job-aaaaaaaa", "reviewer", "xcwds/site"))
			if err == nil || !strings.Contains(err.Error(), "revoked") {
				t.Fatalf("err = %v", err)
			}
			if _, revoked, _ := f.snapshot(); len(revoked) != 1 || !strings.HasPrefix(revoked[0], "ghs_faketoken") {
				t.Errorf("revoked = %v", revoked)
			}
		})
	}
}

func TestRevokeOnJobEnd(t *testing.T) {
	f := newFake(t)
	c := newConn(t, f)
	reg, err := connector.NewRegistry(c)
	if err != nil {
		t.Fatal(err)
	}
	cache := connector.NewCache()
	j := job("job-aaaaaaaa", "implementer", "xcwds/site")
	cred, err := cache.Get(ctx, c, j)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.DropJob(ctx, reg, j.ID); err != nil {
		t.Fatal(err)
	}
	if _, revoked, _ := f.snapshot(); len(revoked) != 1 || revoked[0] != string(cred.Secret.Reveal()) {
		t.Fatalf("revoked = %v", revoked)
	}
}

func TestRefreshBeforeExpiry(t *testing.T) {
	f := newFake(t)
	f.expiresIn = connector.RefreshBefore - time.Minute // already inside the refresh window
	c := newConn(t, f)
	cache := connector.NewCache()
	j := job("job-aaaaaaaa", "reviewer", "xcwds/site")
	a, _ := cache.Get(ctx, c, j)
	b, _ := cache.Get(ctx, c, j)
	if string(a.Secret.Reveal()) == string(b.Secret.Reveal()) {
		t.Fatal("a token about to expire was reused")
	}
	f.mu.Lock()
	f.expiresIn = time.Hour
	f.mu.Unlock()
	x, _ := cache.Get(ctx, c, j)
	y, _ := cache.Get(ctx, c, j)
	if string(x.Secret.Reveal()) != string(y.Secret.Reveal()) {
		t.Fatal("a fresh token was replaced")
	}
}

func TestBackoffAfterFailure(t *testing.T) {
	f := newFake(t)
	f.status = 500
	c := newConn(t, f)
	now := time.Now()
	c.now = func() time.Time { return now }
	j := job("job-aaaaaaaa", "reviewer", "xcwds/site")
	if _, err := c.Mint(ctx, j); err == nil {
		t.Fatal("want the 500")
	}
	_, _, before := f.snapshot()
	if _, err := c.Mint(ctx, j); err == nil || !strings.Contains(err.Error(), "retrying after") {
		t.Fatalf("second mint = %v, want a backoff", err)
	}
	if _, _, after := f.snapshot(); after != before {
		t.Error("the backoff still called GitHub")
	}
	now = now.Add(2 * time.Second)
	f.mu.Lock()
	f.status = 0
	f.mu.Unlock()
	if _, err := c.Mint(ctx, j); err != nil {
		t.Fatalf("after the backoff: %v", err)
	}
}

func TestRateLimitPausesEveryJob(t *testing.T) {
	f := newFake(t)
	f.status, f.retryAfter = 429, "60"
	c := newConn(t, f)
	_, _ = c.Mint(ctx, job("job-aaaaaaaa", "reviewer", "xcwds/site"))
	_, err := c.Mint(ctx, job("job-bbbbbbbb", "reviewer", "xcwds/site"))
	if err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("another job during the rate limit: %v", err)
	}
	if reqs, _, _ := f.snapshot(); len(reqs) != 1 {
		t.Errorf("%d token requests during a rate limit, want 1", len(reqs))
	}
}

func TestTokenNeverPrinted(t *testing.T) {
	f := newFake(t)
	c := newConn(t, f)
	cred, err := c.Mint(ctx, job("job-aaaaaaaa", "reviewer", "xcwds/site"))
	if err != nil {
		t.Fatal(err)
	}
	tok := string(cred.Secret.Reveal())
	for _, out := range []string{fmt.Sprintf("%v", cred), fmt.Sprintf("%+v", cred), fmt.Sprintf("%#v", cred)} {
		if strings.Contains(out, tok) {
			t.Errorf("token printed: %s", out)
		}
	}
	// Errors from GitHub carry its message, never the token.
	f.mu.Lock()
	f.status = 403
	f.mu.Unlock()
	_, err = c.Mint(ctx, job("job-bbbbbbbb", "reviewer", "xcwds/site"))
	if err == nil || strings.Contains(err.Error(), "ghs_") || strings.Contains(err.Error(), "BEGIN") {
		t.Errorf("err = %v", err)
	}
}

func TestKeyProblems(t *testing.T) {
	f := newFake(t)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(testKey)
	for name, key := range map[string][]byte{
		"pkcs8": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
	} {
		c, _ := New(Config{AppID: "12345", InstallationID: 42, PrivateKeySecret: "k", APIURL: f.srv.URL}, secretMap{"k": key})
		if _, err := c.Mint(ctx, job("job-aaaaaaaa", "reviewer", "xcwds/site")); err != nil {
			t.Errorf("%s key: %v", name, err)
		}
	}
	for name, sec := range map[string]secretMap{
		"missing": {},
		"not PEM": {"k": []byte("not a key")},
	} {
		c, _ := New(Config{AppID: "12345", InstallationID: 42, PrivateKeySecret: "k", APIURL: f.srv.URL}, sec)
		_, err := c.Mint(ctx, job("job-aaaaaaaa", "reviewer", "xcwds/site"))
		if err == nil {
			t.Errorf("%s: minted", name)
		}
		if name == "missing" && !errors.Is(err, secrets.ErrNotFound) {
			t.Errorf("missing key: %v", err)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	good := Config{AppID: "1", InstallationID: 2, PrivateKeySecret: "k"}
	if err := good.validate(); err != nil || good.APIURL != DefaultAPIURL || good.Permissions["reviewer"]["contents"] != "read" {
		t.Fatalf("defaults: %v %+v", err, good)
	}
	for name, cfg := range map[string]Config{
		"no app":          {InstallationID: 2, PrivateKeySecret: "k"},
		"no installation": {AppID: "1", PrivateKeySecret: "k"},
		"no key":          {AppID: "1", InstallationID: 2},
		"plain http":      {AppID: "1", InstallationID: 2, PrivateKeySecret: "k", APIURL: "http://github.example.com"},
		"admin level":     {AppID: "1", InstallationID: 2, PrivateKeySecret: "k", Permissions: map[string]map[string]string{"r": {"administration": "admin"}}},
		"empty role":      {AppID: "1", InstallationID: 2, PrivateKeySecret: "k", Permissions: map[string]map[string]string{"r": {}}},
	} {
		if err := cfg.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
