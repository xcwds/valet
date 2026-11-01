package gitproxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/jobs"
	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/pipeline"
	"github.com/xcwds/valet/internal/policy"
	"github.com/xcwds/valet/internal/secrets"
	"github.com/xcwds/valet/internal/store"
	"github.com/xcwds/valet/policies"
)

var ctx = context.Background()

// upstreamToken is what the fake provider mints. It must never reach the
// agent's side.
const upstreamToken = "upstream-only-credential-7f3a"

// forge is a provider connector whose git upstream is a local
// git http-backend.
type forge struct {
	base  string
	token string // minted; upstreamToken unless a test changes it
	mints int
	mu    sync.Mutex
}

func (*forge) Name() string                    { return "forge" }
func (*forge) Actions() []connector.ActionSpec { return nil }
func (f *forge) Mint(context.Context, jobs.Job) (connector.Credential, error) {
	f.mu.Lock()
	f.mints++
	f.mu.Unlock()
	return connector.Credential{Secret: secrets.NewSecret([]byte(f.token)), ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (*forge) Execute(context.Context, connector.Credential, jobs.Job, connector.Action) (connector.Result, error) {
	return connector.Result{}, nil
}

func (*forge) GitRepo(raw string) (string, error) {
	r := strings.ToLower(raw)
	if strings.Count(r, "/") != 1 || strings.Contains(r, "..") {
		return "", fmt.Errorf("bad repo %q", raw)
	}
	return r, nil
}

func (f *forge) GitURL(repo string) (*url.URL, error) { return url.Parse(f.base + "/" + repo + ".git") }

func (*forge) GitAuth(r *http.Request, cred connector.Credential) {
	r.SetBasicAuth("x-access-token", string(cred.Secret.Reveal()))
}

// upstreamCall is a request the upstream received.
type upstreamCall struct {
	Method, Path, Query string
	Header              http.Header
}

type env struct {
	t        *testing.T
	root     string // upstream repositories: root/xcwds/site.git
	proxy    *httptest.Server
	forge    *forge
	db       *store.Store
	jobs     *jobs.Service
	mu       sync.Mutex
	upstream []upstreamCall
	toClient bytes.Buffer // every header and body byte the proxy sent back
}

func newEnv(t *testing.T) *env {
	t.Helper()
	// Locally, no git means skip; in CI these tests must run.
	skip := t.Skip
	if os.Getenv("CI") != "" {
		skip = t.Fatal
	}
	backend, err := exec.LookPath("git")
	if err != nil {
		skip("git not installed")
	}
	out, err := exec.Command(backend, "--exec-path").Output()
	if err != nil {
		t.Fatal(err)
	}
	httpBackend := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if _, err := os.Stat(httpBackend); err != nil {
		skip("git-http-backend not installed")
	}

	e := &env{t: t, root: t.TempDir()}
	e.seed("xcwds/site")
	e.seed("xcwds/other")

	cgiHandler := &cgi.Handler{Path: httpBackend, Env: []string{"GIT_PROJECT_ROOT=" + e.root, "GIT_HTTP_EXPORT_ALL=1"}}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.upstream = append(e.upstream, upstreamCall{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone()})
		e.mu.Unlock()
		if u, p, ok := r.BasicAuth(); !ok || u != "x-access-token" || p != upstreamToken {
			w.Header().Set("WWW-Authenticate", `Basic realm="upstream"`)
			http.Error(w, "bad credentials", http.StatusUnauthorized)
			return
		}
		if r.ContentLength < 0 {
			// net/http/cgi refuses chunked bodies (real hosts accept
			// them, and git sends them for large pushes): buffer.
			b, _ := io.ReadAll(r.Body)
			r.Body, r.ContentLength, r.TransferEncoding = io.NopCloser(bytes.NewReader(b)), int64(len(b)), nil
		}
		cgiHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(up.Close)

	e.db, err = store.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.db.Close() })
	log := logging.New(io.Discard, "json", slog.LevelInfo)
	alog := audit.New(e.db, log)
	e.forge = &forge{base: up.URL, token: upstreamToken}
	reg, err := connector.NewRegistry(e.forge, Actions{})
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.LoadFS("defaults", policies.Defaults)
	if err != nil {
		t.Fatal(err)
	}
	e.jobs = jobs.NewService(e.db, alog)
	pl := pipeline.New(reg, pol, alog, connector.NewCache(), log)
	mux := http.NewServeMux()
	mux.Handle(Prefix, New(reg, pl, log))
	e.proxy = httptest.NewServer(e.jobs.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(&tee{ResponseWriter: w, e: e}, r)
	})))
	t.Cleanup(e.proxy.Close)
	return e
}

// tee records what the proxy sends the client.
type tee struct {
	http.ResponseWriter
	e     *env
	wrote bool
}

func (t *tee) WriteHeader(code int) {
	t.record()
	t.ResponseWriter.WriteHeader(code)
}

func (t *tee) Write(b []byte) (int, error) {
	t.record()
	t.e.mu.Lock()
	t.e.toClient.Write(b)
	t.e.mu.Unlock()
	return t.ResponseWriter.Write(b)
}

func (t *tee) record() {
	if t.wrote {
		return
	}
	t.wrote = true
	t.e.mu.Lock()
	_ = t.Header().Write(&t.e.toClient)
	t.e.mu.Unlock()
}

func (t *tee) Flush() {
	if f, ok := t.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// seed creates a bare upstream repository with one commit on main.
func (e *env) seed(repo string) {
	bare := filepath.Join(e.root, repo+".git")
	work := e.t.TempDir()
	e.git(work, "init", "-q", "-b", "main")
	e.git(work, "commit", "-q", "--allow-empty", "-m", "initial")
	e.git(e.root, "clone", "-q", "--bare", work, bare)
	e.git(bare, "config", "http.receivepack", "true")
	e.git(bare, "config", "receive.advertisePushOptions", "true")
}

// git runs git in dir with a clean configuration.
func (e *env) git(dir string, args ...string) string {
	e.t.Helper()
	out, err := e.gitErr(dir, "", args...)
	if err != nil {
		e.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// gitErr runs git as an agent holding token would: the documented
// credential helper hands git the session token.
func (e *env) gitErr(dir, token string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{
		"-c", "user.name=agent", "-c", "user.email=agent@example.com", "-c", "init.defaultBranch=main",
		"-c", `credential.helper=!f() { test "$1" = get && echo username=valet && echo "password=$VALET_TOKEN"; }; f`,
	}, args...)...)
	cmd.Dir = dir
	cmd.Env = []string{"HOME=" + e.t.TempDir(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "PATH=" + os.Getenv("PATH"), "VALET_TOKEN=" + token}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (e *env) job(role string, repos ...string) (jobs.Job, string) {
	e.t.Helper()
	j, tok, err := e.jobs.Create(ctx, jobs.CreateRequest{Role: role, Repos: repos, CreatedBy: "admin:test", TTL: time.Hour})
	if err != nil {
		e.t.Fatal(err)
	}
	return j, tok
}

func (e *env) url(repo string) string { return e.proxy.URL + "/git/forge/" + repo + ".git" }

func (e *env) pushesUpstream() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, c := range e.upstream {
		if c.Method == "POST" && strings.HasSuffix(c.Path, "/git-receive-pack") {
			n++
		}
	}
	return n
}

func (e *env) upstreamRef(repo, ref string) string {
	out, _ := exec.Command("git", "--git-dir", filepath.Join(e.root, repo+".git"), "rev-parse", "--verify", "-q", ref).Output()
	return strings.TrimSpace(string(out))
}

func (e *env) audit(jobID string) []audit.Record {
	e.t.Helper()
	recs, err := audit.Tail(ctx, e.db.Read(), audit.Filter{JobID: jobID, Limit: 1000})
	if err != nil {
		e.t.Fatal(err)
	}
	return recs
}

// waitRecord waits up to 5 s for the job's first audit record matching
// match: results are written when a transfer ends, which may be just
// after the client has its response.
func (e *env) waitRecord(jobID string, match func(audit.Record) bool) audit.Record {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, r := range e.audit(jobID) {
			if match(r) {
				return r
			}
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("no matching audit record for %s: %+v", jobID, e.audit(jobID))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// clone clones repo for the job and returns the work tree.
func (e *env) clone(token, repo string) string {
	e.t.Helper()
	dir := filepath.Join(e.t.TempDir(), "w")
	if out, err := e.gitErr(filepath.Dir(dir), token, "clone", "-q", e.url(repo), dir); err != nil {
		e.t.Fatalf("clone: %v\n%s", err, out)
	}
	return dir
}

func TestCloneFetchAndPushOwnBranch(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job("implementer", "xcwds/site")
	dir := e.clone(tok, "xcwds/site")
	if out, err := e.gitErr(dir, tok, "fetch", "-q", "origin"); err != nil {
		t.Fatalf("fetch: %v\n%s", err, out)
	}

	branch := "agent/" + j.ID + "/fix"
	e.git(dir, "commit", "-q", "--allow-empty", "-m", "fix")
	head := strings.TrimSpace(e.git(dir, "rev-parse", "HEAD"))
	if out, err := e.gitErr(dir, tok, "push", "-o", "ci.skip", "origin", "HEAD:refs/heads/"+branch); err != nil {
		t.Fatalf("push to own branch: %v\n%s", err, out)
	}
	if got := e.upstreamRef("xcwds/site", "refs/heads/"+branch); got != head {
		t.Fatalf("upstream %s = %q, want %s", branch, got, head)
	}

	var push *audit.Record
	for _, r := range e.audit(j.ID) {
		if r.Action == "git.push" && r.Decision == audit.Allow {
			push = &r
		}
	}
	if push == nil || push.Rule != "implementer/push-own-branch" || push.Interface != audit.InterfaceGit ||
		!strings.Contains(string(push.Params), `"name":"refs/heads/`+branch+`"`) || !strings.Contains(string(push.Params), `"delete":false`) {
		t.Fatalf("push audit = %+v", push)
	}
	if e.forge.mints != 1 {
		t.Errorf("%d mints for one job, want 1 (cached)", e.forge.mints)
	}
}

func TestDeniedPushesNeverReachUpstream(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job("implementer", "xcwds/site")
	other, _ := e.job("implementer", "xcwds/site")
	dir := e.clone(tok, "xcwds/site")
	e.git(dir, "commit", "-q", "--allow-empty", "-m", "change")
	own := "refs/heads/agent/" + j.ID + "/keep"
	if out, err := e.gitErr(dir, tok, "push", "origin", "HEAD:"+own); err != nil {
		t.Fatalf("setup push: %v\n%s", err, out)
	}
	before := e.pushesUpstream()
	mainBefore := e.upstreamRef("xcwds/site", "refs/heads/main")

	for name, args := range map[string][]string{
		"main":               {"push", "origin", "HEAD:refs/heads/main"},
		"another job branch": {"push", "origin", "HEAD:refs/heads/agent/" + other.ID + "/x"},
		"delete own branch":  {"push", "origin", ":" + own},
		"tag":                {"push", "origin", "HEAD:refs/tags/v1"},
		"one bad ref of two": {"push", "origin", "HEAD:refs/heads/agent/" + j.ID + "/ok", "HEAD:refs/heads/main"},
		"force main":         {"push", "-f", "origin", "HEAD~0:refs/heads/main"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := e.gitErr(dir, tok, args...)
			if err == nil {
				t.Fatalf("push succeeded:\n%s", out)
			}
			if !strings.Contains(out, "[remote rejected]") || !strings.Contains(out, "implementer/push-elsewhere") {
				t.Errorf("git didn't show the refusal:\n%s", out)
			}
		})
	}
	if n := e.pushesUpstream(); n != before {
		t.Errorf("%d denied pushes reached upstream", n-before)
	}
	if e.upstreamRef("xcwds/site", "refs/heads/main") != mainBefore || e.upstreamRef("xcwds/site", "refs/heads/agent/"+j.ID+"/ok") != "" ||
		e.upstreamRef("xcwds/site", own) == "" || e.upstreamRef("xcwds/site", "refs/tags/v1") != "" {
		t.Error("an upstream ref changed")
	}
	denials := 0
	for _, r := range e.audit(j.ID) {
		if r.Action == "git.push" && r.Decision == audit.Deny && r.Rule == "implementer/push-elsewhere" {
			denials++
		}
	}
	if denials != 6 {
		t.Errorf("%d denied pushes audited, want 6", denials)
	}
}

func TestFetchIsScopedToTheJob(t *testing.T) {
	e := newEnv(t)
	_, tok := e.job("implementer", "xcwds/site")
	out, err := e.gitErr(t.TempDir(), tok, "clone", e.url("xcwds/other"), "o")
	if err == nil || !strings.Contains(out, "403") {
		t.Fatalf("clone of a repo outside the job: %v\n%s", err, out)
	}
	if !strings.Contains(out, "denied") {
		t.Errorf("git didn't show the reason:\n%s", out)
	}
	_, reviewer := e.job("reviewer", "xcwds/site")
	dir := e.clone(reviewer, "xcwds/site")
	e.git(dir, "commit", "-q", "--allow-empty", "-m", "x")
	if out, err := e.gitErr(dir, reviewer, "push", "origin", "HEAD:refs/heads/agent/x/y"); err == nil {
		t.Fatalf("a reviewer pushed:\n%s", out)
	}
	if out, err := e.gitErr(t.TempDir(), "vlt_sess_"+strings.Repeat("a", 52), "clone", e.url("xcwds/site"), "x"); err == nil {
		t.Fatalf("clone with a bogus token:\n%s", out)
	}
}

func TestOnlySmartHTTPEndpoints(t *testing.T) {
	e := newEnv(t)
	_, tok := e.job("implementer", "xcwds/site")
	for _, c := range []struct{ method, path string }{
		{"GET", "/git/forge/xcwds/site.git/info/refs"}, // dumb HTTP
		{"GET", "/git/forge/xcwds/site.git/info/refs?service=git-upload-archive"},
		{"GET", "/git/forge/xcwds/site.git/info/refs?service=git-upload-pack&x=1"},
		{"GET", "/git/forge/xcwds/site.git/HEAD"},
		{"GET", "/git/forge/xcwds/site.git/objects/info/packs"},
		{"GET", "/git/forge/xcwds/site.git/git-upload-pack"},
		{"POST", "/git/forge/xcwds/site.git/info/refs?service=git-upload-pack"},
		{"GET", "/git/nope/xcwds/site.git/info/refs?service=git-upload-pack"},
		{"GET", "/git/forge/xcwds/site/extra.git/info/refs?service=git-upload-pack"},
		{"GET", "/git/forge/xcwds/..%2fother.git/info/refs?service=git-upload-pack"},
	} {
		req, _ := http.NewRequest(c.method, e.proxy.URL+c.path, nil)
		req.SetBasicAuth("valet", tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s: %d, want 404", c.method, c.path, resp.StatusCode)
		}
	}
	if len(e.upstream) != 0 {
		t.Errorf("upstream saw %d requests", len(e.upstream))
	}
}

// reply is a response with its body read.
type reply struct {
	StatusCode int
	Header     http.Header
}

func post(t *testing.T, e *env, tok, path string, body []byte, gz bool) (reply, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", e.proxy.URL+path, bytes.NewReader(body))
	req.SetBasicAuth("valet", tok)
	req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return reply{resp.StatusCode, resp.Header}, string(b)
}

func TestMalformedPushesDeny(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job("implementer", "xcwds/site")
	sha := strings.Repeat("1", 40)
	zero := strings.Repeat("0", 40)
	path := "/git/forge/xcwds/site.git/git-receive-pack"
	for name, body := range map[string]string{
		"garbage":          "not a pkt-line at all",
		"truncated":        pkt(zero+" "+sha+" refs/heads/agent/"+j.ID+"/x\x00report-status") + "00",
		"no flush":         pkt(zero + " " + sha + " refs/heads/agent/" + j.ID + "/x\x00report-status"),
		"bad sha":          pkt("xyz "+sha+" refs/heads/agent/"+j.ID+"/x\x00") + "0000",
		"bad ref name":     pkt(zero+" "+sha+" refs/heads/agent/"+j.ID+"/../../main\x00") + "0000",
		"oversized length": "ffff" + strings.Repeat("a", 100),
		"special packet":   "0001" + "0000",
		"flush then data":  "0000PACK",
		"push cert":        pkt("push-cert\x00report-status\n") + "0000",
	} {
		t.Run(name, func(t *testing.T) {
			resp, text := post(t, e, tok, path, []byte(body), false)
			if resp.StatusCode != http.StatusForbidden || !strings.Contains(text, "malformed") {
				t.Errorf("%d %q", resp.StatusCode, text)
			}
		})
	}
	resp, _ := post(t, e, tok, path, []byte("not gzip"), true)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("bad gzip: %d", resp.StatusCode)
	}
	if n := e.pushesUpstream(); n != 0 {
		t.Errorf("%d malformed pushes reached upstream", n)
	}
	n := 0
	for _, r := range e.audit(j.ID) {
		if r.Action == "git.push" && r.Decision == audit.Deny && r.Error == "invalid params" {
			n++
		}
	}
	if n != 10 {
		t.Errorf("%d malformed pushes audited, want 10", n)
	}
}

func TestGzipPushIsParsed(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job("implementer", "xcwds/site")
	sha := strings.Repeat("1", 40)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = io.WriteString(zw, pkt(sha+" "+strings.Repeat("2", 40)+" refs/heads/main\x00report-status side-band-64k")+"0000"+"PACK...")
	_ = zw.Close()
	resp, text := post(t, e, tok, "/git/forge/xcwds/site.git/git-receive-pack", buf.Bytes(), true)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-git-receive-pack-result" ||
		!strings.Contains(text, "ng refs/heads/main denied by rule implementer/push-elsewhere") {
		t.Fatalf("%d %q", resp.StatusCode, text)
	}
	recs := e.audit(j.ID)
	if last := recs[len(recs)-1]; last.Action != "git.push" || !strings.Contains(string(last.Params), `"name":"refs/heads/main"`) {
		t.Errorf("audit = %+v", last)
	}
}

func TestCredentialsStayOnTheirSide(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job("implementer", "xcwds/site")
	dir := e.clone(tok, "xcwds/site")
	e.git(dir, "commit", "-q", "--allow-empty", "-m", "x")
	if out, err := e.gitErr(dir, tok, "push", "origin", "HEAD:refs/heads/agent/"+j.ID+"/x"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	_, _ = e.gitErr(dir, tok, "push", "origin", "HEAD:refs/heads/main")

	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.upstream) == 0 {
		t.Fatal("nothing reached upstream")
	}
	sessionB64 := base64.StdEncoding.EncodeToString([]byte("valet:" + tok))
	for _, c := range e.upstream {
		h := fmt.Sprint(c.Header)
		if strings.Contains(h, tok) || strings.Contains(h, sessionB64) {
			t.Errorf("the session token reached upstream: %s %s", c.Method, c.Path)
		}
		if strings.Contains(h, "X-Forwarded") || c.Header.Get("Cookie") != "" {
			t.Errorf("forwarded headers upstream: %v", c.Header)
		}
	}
	upstreamB64 := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + upstreamToken))
	if s := e.toClient.String(); strings.Contains(s, upstreamToken) || strings.Contains(s, upstreamB64) {
		t.Error("the upstream token reached the client")
	}
}

func TestUpstreamRefusingTheCredentialIsNot401(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job("implementer", "xcwds/site")
	e.forge.token = "revoked-upstream" // the upstream answers 401
	req, _ := http.NewRequest("GET", e.url("xcwds/site")+"/info/refs?service=git-upload-pack", nil)
	req.SetBasicAuth("valet", tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	// A 401 would make git ask the agent for a password it doesn't have.
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get("WWW-Authenticate") != "" {
		t.Errorf("%d %v", resp.StatusCode, resp.Header)
	}
	// The result is recorded once the transfer ends, which can be just
	// after the client has its response.
	res := e.waitRecord(j.ID, func(r audit.Record) bool { return r.Decision == audit.Info })
	if res.UpstreamStatus != 401 || res.Error == "" {
		t.Errorf("result = %+v", res)
	}
}

// A push with a few MB of incompressible data streams through (chunked,
// as git sends large pushes) and lands upstream intact.
func TestLargePushStreams(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job("implementer", "xcwds/site")
	dir := e.clone(tok, "xcwds/site")
	blob := make([]byte, 6<<20)
	for i := range blob {
		blob[i] = byte(i*7919 + i>>8) // poorly compressible, deterministic
	}
	if err := os.WriteFile(filepath.Join(dir, "big.bin"), blob, 0o600); err != nil {
		t.Fatal(err)
	}
	e.git(dir, "add", "big.bin")
	e.git(dir, "commit", "-q", "-m", "big")
	head := strings.TrimSpace(e.git(dir, "rev-parse", "HEAD"))
	ref := "refs/heads/agent/" + j.ID + "/big"
	if out, err := e.gitErr(dir, tok, "-c", "http.postBuffer=65536", "push", "origin", "HEAD:"+ref); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := e.upstreamRef("xcwds/site", ref); got != head {
		t.Fatalf("upstream %s = %q, want %s", ref, got, head)
	}
	clone := e.clone(tok, "xcwds/site")
	if out, err := e.gitErr(clone, tok, "fetch", "-q", "origin", ref); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := strings.TrimSpace(e.git(clone, "rev-parse", "FETCH_HEAD")); got != head {
		t.Errorf("fetched %s, want %s", got, head)
	}
}

// Before a large chunked push git probes with a body of only "0000". It
// changes nothing, so it is checked as a fetch and forwarded.
func TestPushProbeIsAFetch(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job("implementer", "xcwds/site")
	resp, _ := post(t, e, tok, "/git/forge/xcwds/site.git/git-receive-pack", []byte("0000"), false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("probe: %d", resp.StatusCode)
	}
	d := e.waitRecord(j.ID, func(r audit.Record) bool { return r.Interface == audit.InterfaceGit && r.Decision != audit.Info })
	if d.Action != "git.fetch" || d.Decision != audit.Allow {
		t.Errorf("probe decision = %+v", d)
	}
	e.waitRecord(j.ID, func(r audit.Record) bool { return r.Action == "git.fetch" && r.Decision == audit.Info })
	// The same probe for a repo outside the job is denied.
	if resp, _ := post(t, e, tok, "/git/forge/xcwds/other.git/git-receive-pack", []byte("0000"), false); resp.StatusCode != http.StatusForbidden {
		t.Errorf("probe outside the job: %d", resp.StatusCode)
	}
}

// A transfer the client abandons is not audited as completed.
func TestAbortedTransferIsRecordedAsFailed(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job("implementer", "xcwds/site")
	released := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		_, _ = io.WriteString(w, "001e# service=git-upload-pack\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done() // never finishes on its own
		close(released)
	}))
	t.Cleanup(slow.Close)
	e.forge.base = slow.URL

	cctx, cancel := context.WithCancel(ctx)
	req, _ := http.NewRequestWithContext(cctx, "GET", e.url("xcwds/site")+"/info/refs?service=git-upload-pack", nil)
	req.SetBasicAuth("valet", tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(resp.Body, make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = resp.Body.Close()
	<-released

	deadline := time.Now().Add(5 * time.Second)
	for {
		recs := e.audit(j.ID)
		last := recs[len(recs)-1]
		if last.Decision == audit.Info {
			if last.UpstreamStatus != 200 || !strings.Contains(last.Error, "client disconnected") {
				t.Errorf("result = %+v", last)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no result recorded: %+v", recs[len(recs)-2:])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestUpstreamHonorsTheOperatorsProxy(t *testing.T) {
	tr, ok := New(nil, nil, slog.New(slog.DiscardHandler)).transport.(*http.Transport)
	if !ok || tr.Proxy == nil {
		t.Fatal("the upstream transport ignores HTTPS_PROXY, unlike the connectors' API calls")
	}
}

// An upstream that dies mid-response is recorded as failed, not as its
// 200.
func TestUpstreamDyingMidStreamIsRecorded(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job("implementer", "xcwds/site")
	dying := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = io.WriteString(w, "001e# service=git-upload-pack\n")
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler) // drop the connection short of 1000 bytes
	}))
	t.Cleanup(dying.Close)
	e.forge.base = dying.URL
	req, _ := http.NewRequest("GET", e.url("xcwds/site")+"/info/refs?service=git-upload-pack", nil)
	req.SetBasicAuth("valet", tok)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		recs := e.audit(j.ID)
		if last := recs[len(recs)-1]; last.Decision == audit.Info {
			if last.Error == "" {
				t.Errorf("a broken transfer recorded as success: %+v", last)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no result recorded")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
