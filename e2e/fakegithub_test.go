package e2e

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fake GitHub App settings the harness configures valetd with.
const (
	appID          = "1001"
	installationID = 4242
	accountLogin   = "xcwds"
)

// Call is one request fake GitHub received.
type Call struct {
	Method, Path string
	Token        string // the installation token used, "" for App JWT calls
	Body         map[string]any
}

// Grant is what one minted installation token may do.
type Grant struct {
	Token       string
	Repos       []string // owner/name
	Permissions map[string]string
}

// FakeGitHub implements the App token endpoints and the v1 actions'
// endpoints the scenarios use, and enforces each token's grant the way
// GitHub does, so a token broader than it should be would show.
type FakeGitHub struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey

	mu      sync.Mutex
	calls   []Call
	grants  map[string]Grant
	revoked []string
	prs     map[int]bool     // number → exists as a PR (else an issue)
	pulls   []map[string]any // pull requests opened with POST /pulls

	gitRoot string // bare repositories, gitRoot/owner/name.git
	git     *cgi.Handler
}

// NewFakeGitHub starts it. PR #7 exists on every repository; #8 is an issue.
func NewFakeGitHub(t *testing.T) *FakeGitHub {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &FakeGitHub{t: t, key: key, grants: map[string]Grant{}, prs: map[int]bool{7: true, 8: false}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// URL is the API base URL.
func (f *FakeGitHub) URL() string { return f.srv.URL }

// PrivateKeyPEM is the App's private key, generated for this run.
func (f *FakeGitHub) PrivateKeyPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.key)})
}

// Calls returns every request so far, in order.
func (f *FakeGitHub) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// Grants returns the tokens minted so far, in order.
func (f *FakeGitHub) Grants() []Grant {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Grant
	for _, c := range f.calls {
		if c.Path == fmt.Sprintf("/app/installations/%d/access_tokens", installationID) {
			if g, ok := f.grants[c.Token]; ok {
				out = append(out, g)
			}
		}
	}
	return out
}

// ActionCalls returns the calls made with an installation token: what an
// agent's actions did upstream.
func (f *FakeGitHub) ActionCalls() []Call {
	var out []Call
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Path, "/repos/") {
			out = append(out, c)
		}
	}
	return out
}

func (f *FakeGitHub) validJWT(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(tok, ".")
	if !ok || len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&f.key.PublicKey, crypto.SHA256, sum[:], sig) != nil {
		return false
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		Iss      string
		Iat, Exp int64
	}
	_ = json.Unmarshal(raw, &c)
	now := time.Now().Unix()
	return c.Iss == appID && c.Iat <= now && c.Exp > now
}

var repoPath = regexp.MustCompile(`^/repos/([a-z0-9._-]+/[a-z0-9._-]+)(/.*)?$`)

// need says which permission an endpoint requires, as GitHub documents it.
func need(method, rest string) (perm, level string) {
	switch {
	case method == http.MethodPost && rest == "/pulls":
		return "pull_requests", "write"
	case strings.HasSuffix(rest, "/merge"):
		return "contents", "write"
	case strings.HasSuffix(rest, "/comments"), strings.HasSuffix(rest, "/reviews"):
		return "pull_requests", "write"
	case strings.HasPrefix(rest, "/issues/"):
		return "pull_requests", "read"
	case method == http.MethodGet:
		return "metadata", "read"
	default:
		return "contents", "write"
	}
}

func allows(have, level string) bool {
	return have == "write" || (level == "read" && have == "read")
}

func (f *FakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	if gitPath.MatchString(r.URL.Path) {
		f.serveGit(w, r)
		return
	}
	var body map[string]any
	if b, _ := io.ReadAll(r.Body); len(b) > 0 {
		_ = json.Unmarshal(b, &body)
	}
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	call := Call{Method: r.Method, Path: r.URL.Path, Body: body}
	if !strings.HasPrefix(r.URL.Path, "/app/") {
		call.Token = tok
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(status int, v any) {
		f.calls = append(f.calls, call)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") == "" {
		reply(400, map[string]string{"message": "missing GitHub headers"})
		return
	}

	switch {
	case r.Method == "GET" && r.URL.Path == fmt.Sprintf("/app/installations/%d", installationID):
		if !f.validJWT(r) {
			reply(401, map[string]string{"message": "Bad credentials"})
			return
		}
		reply(200, map[string]any{"id": installationID, "account": map[string]string{"login": accountLogin}})
		return
	case r.Method == "POST" && r.URL.Path == fmt.Sprintf("/app/installations/%d/access_tokens", installationID):
		if !f.validJWT(r) {
			reply(401, map[string]string{"message": "Bad credentials"})
			return
		}
		g := Grant{Token: fmt.Sprintf("ghs_e2e%d", len(f.grants)+1), Permissions: map[string]string{"metadata": "read"}}
		perms, _ := body["permissions"].(map[string]any)
		for k, v := range perms {
			g.Permissions[k], _ = v.(string)
		}
		names, _ := body["repositories"].([]any)
		var repos []map[string]string
		for _, n := range names {
			s, _ := n.(string)
			g.Repos = append(g.Repos, accountLogin+"/"+s)
			repos = append(repos, map[string]string{"full_name": accountLogin + "/" + s})
		}
		f.grants[g.Token] = g
		call.Token = g.Token // record which token this mint produced
		reply(201, map[string]any{
			"token": g.Token, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			"permissions": g.Permissions, "repository_selection": "selected", "repositories": repos,
		})
		return
	case r.Method == "DELETE" && r.URL.Path == "/installation/token":
		f.revoked = append(f.revoked, tok)
		delete(f.grants, tok)
		w.WriteHeader(204)
		f.calls = append(f.calls, call)
		return
	}

	m := repoPath.FindStringSubmatch(r.URL.Path)
	if m == nil {
		reply(404, map[string]string{"message": "Not Found"})
		return
	}
	repo, rest := m[1], m[2]
	g, ok := f.grants[tok]
	if !ok {
		reply(401, map[string]string{"message": "Bad credentials"})
		return
	}
	if !slices.Contains(g.Repos, repo) {
		reply(404, map[string]string{"message": "Not Found"}) // GitHub hides repos a token can't see
		return
	}
	perm, level := need(r.Method, rest)
	if !allows(g.Permissions[perm], level) {
		reply(403, map[string]string{"message": "Resource not accessible by integration"})
		return
	}

	if r.Method == http.MethodPost && rest == "/pulls" {
		f.pulls = append(f.pulls, body)
		n := 100 + len(f.pulls)
		reply(201, map[string]any{"number": n, "html_url": fmt.Sprintf("https://github.com/%s/pull/%d", repo, n)})
		return
	}

	seg := strings.Split(strings.Trim(rest, "/"), "/")
	number := 0
	if len(seg) >= 2 {
		number, _ = strconv.Atoi(seg[1])
	}
	isPR, exists := f.prs[number]
	if !exists {
		reply(404, map[string]string{"message": "Not Found"})
		return
	}
	html := fmt.Sprintf("https://github.com/%s/pull/%d", repo, number)
	switch {
	case r.Method == "GET" && len(seg) == 2 && seg[0] == "issues":
		v := map[string]any{"number": number, "title": "Fix the thing", "state": "open"}
		if isPR {
			v["pull_request"] = map[string]string{"url": html}
		}
		reply(200, v)
	case r.Method == "POST" && len(seg) == 3 && seg[0] == "issues" && seg[2] == "comments":
		reply(201, map[string]any{"id": 9001, "html_url": html + "#issuecomment-9001"})
	case r.Method == "POST" && len(seg) == 3 && seg[0] == "pulls" && seg[2] == "reviews" && isPR:
		reply(200, map[string]any{"id": 5001, "state": body["event"], "html_url": html + "#pullrequestreview-5001"})
	case r.Method == "PUT" && len(seg) == 3 && seg[0] == "pulls" && seg[2] == "merge" && isPR:
		reply(200, map[string]any{"merged": true, "sha": strings.Repeat("a", 40), "message": "merged"})
	default:
		reply(404, map[string]string{"message": "Not Found"})
	}
}

// gitPath matches git smart-HTTP requests: /owner/name.git/...
var gitPath = regexp.MustCompile(`^/([a-z0-9._-]+/[a-z0-9._-]+)\.git/`)

// HostRepo creates a bare repository with one commit on main, served over
// git smart HTTP at /owner/name.git like github.com. The connector is
// pointed at it with git_url.
func (f *FakeGitHub) HostRepo(repo string) {
	f.t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		f.t.Skip("git not installed")
	}
	f.mu.Lock()
	if f.gitRoot == "" {
		f.gitRoot = f.t.TempDir()
		out, err := exec.Command(git, "--exec-path").Output()
		if err != nil {
			f.mu.Unlock()
			f.t.Fatal(err)
		}
		backend := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
		f.git = &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + f.gitRoot, "GIT_HTTP_EXPORT_ALL=1"}}
	}
	root := f.gitRoot
	f.mu.Unlock()
	work := f.t.TempDir()
	bare := filepath.Join(root, repo+".git")
	for _, args := range [][]string{
		{"-C", work, "init", "-q", "-b", "main"},
		{"-C", work, "-c", "user.name=owner", "-c", "user.email=owner@example.com", "commit", "-q", "--allow-empty", "-m", "initial"},
		{"clone", "-q", "--bare", work, bare},
		{"-C", bare, "config", "http.receivepack", "true"},
	} {
		if out, err := exec.Command(git, args...).CombinedOutput(); err != nil {
			f.t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

// Ref returns a ref's commit in a hosted repository, or "".
func (f *FakeGitHub) Ref(repo, ref string) string {
	out, _ := exec.Command("git", "--git-dir", filepath.Join(f.gitRoot, repo+".git"), "rev-parse", "--verify", "-q", ref).Output()
	return strings.TrimSpace(string(out))
}

// Pulls returns the pull requests opened so far.
func (f *FakeGitHub) Pulls() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.pulls)
}

// serveGit serves git smart HTTP for hosted repositories, accepting only an
// installation token whose grant covers the repository, as GitHub does:
// contents read to fetch, contents write to push.
func (f *FakeGitHub) serveGit(w http.ResponseWriter, r *http.Request) {
	repo := gitPath.FindStringSubmatch(r.URL.Path)[1]
	user, tok, _ := r.BasicAuth()
	push := strings.HasSuffix(r.URL.Path, "/git-receive-pack") || r.URL.Query().Get("service") == "git-receive-pack"
	f.mu.Lock()
	f.calls = append(f.calls, Call{Method: r.Method, Path: r.URL.Path, Token: tok})
	g, ok := f.grants[tok]
	handler := f.git
	f.mu.Unlock()
	level := "read"
	if push {
		level = "write"
	}
	switch {
	case user != "x-access-token" || !ok:
		w.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
		http.Error(w, "bad credentials", http.StatusUnauthorized)
		return
	case !slices.Contains(g.Repos, repo) || handler == nil:
		http.Error(w, "Repository not found.", http.StatusNotFound)
		return
	case !allows(g.Permissions["contents"], level):
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}
	if r.ContentLength < 0 {
		// net/http/cgi refuses chunked bodies; GitHub takes them.
		b, _ := io.ReadAll(r.Body)
		r.Body, r.ContentLength, r.TransferEncoding = io.NopCloser(bytes.NewReader(b)), int64(len(b)), nil
	}
	handler.ServeHTTP(w, r)
}

// GitCalls returns the git requests that reached the fake, in order.
func (f *FakeGitHub) GitCalls() []Call {
	var out []Call
	for _, c := range f.Calls() {
		if gitPath.MatchString(c.Path) {
			out = append(out, c)
		}
	}
	return out
}
