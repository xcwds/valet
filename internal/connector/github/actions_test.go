package github

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

type recorded struct {
	Method, Path, Query, Accept, Auth string
	Body                              map[string]any
}

// apiFake answers the action endpoints with canned responses.
type apiFake struct {
	mu   sync.Mutex
	srv  *httptest.Server
	reqs []recorded
	// responses by "METHOD /path": status and body
	resp map[string]struct {
		status int
		body   string
	}
}

func newAPIFake(t *testing.T) *apiFake {
	f := &apiFake{resp: map[string]struct {
		status int
		body   string
	}{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		rec := recorded{Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery, Accept: r.Header.Get("Accept"), Auth: r.Header.Get("Authorization")}
		if b, _ := io.ReadAll(r.Body); len(b) > 0 {
			_ = json.Unmarshal(b, &rec.Body)
		}
		f.reqs = append(f.reqs, rec)
		res, ok := f.resp[r.Method+" "+r.URL.EscapedPath()]
		if !ok {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
			return
		}
		w.WriteHeader(res.status)
		_, _ = w.Write([]byte(res.body))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *apiFake) on(method, path string, status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resp[method+" "+path] = struct {
		status int
		body   string
	}{status, body}
}

func (f *apiFake) last() recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reqs[len(f.reqs)-1]
}

func (f *apiFake) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

var cred = connector.Credential{Secret: secrets.NewSecret([]byte("ghs_installtoken"))}

func execute(t *testing.T, f *apiFake, action, params string) (connector.Result, error) {
	t.Helper()
	c, err := New(Config{AppID: "1", InstallationID: 42, PrivateKeySecret: "k", APIURL: f.srv.URL}, secretMap{})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := connector.NewRegistry(c)
	if err != nil {
		t.Fatal(err)
	}
	a, _, _, err := reg.Resolve("github."+action, json.RawMessage(params))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return c.Execute(ctx, cred, jobs.Job{}, a)
}

func body(t *testing.T, r connector.Result) map[string]any {
	t.Helper()
	b, _ := json.Marshal(r.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func TestActions(t *testing.T) {
	cases := []struct {
		action, params    string
		method, path      string
		status            int
		reply             string
		wantReq, wantBody map[string]any
		check             func(t *testing.T, got map[string]any, rec recorded)
	}{
		{
			"repo.read", `{"repo":"xcwds/site"}`, "GET", "/repos/xcwds/site", 200,
			`{"full_name":"xcwds/site","default_branch":"main","private":true,"owner":{"login":"xcwds"},"permissions":{"admin":true}}`,
			nil,
			map[string]any{"full_name": "xcwds/site", "default_branch": "main", "private": true},
			nil,
		},
		{
			"issue.read", `{"repo":"xcwds/site","number":3}`, "GET", "/repos/xcwds/site/issues/3", 200,
			`{"number":3,"title":"t","state":"open","body":"b","user":{"login":"u"},"labels":[{"name":"bug"}],"comments":2}`,
			nil,
			map[string]any{"number": float64(3), "author": "u", "is_pull_request": false},
			nil,
		},
		{
			"issue.comment", `{"repo":"xcwds/site","number":3,"body":"hi"}`, "POST", "/repos/xcwds/site/issues/3/comments", 201,
			`{"id":9,"html_url":"https://github.com/x"}`,
			map[string]any{"body": "hi"},
			map[string]any{"id": float64(9)},
			nil,
		},
		{
			"pr.comment", `{"repo":"xcwds/site","number":7,"body":"lgtm"}`, "POST", "/repos/xcwds/site/issues/7/comments", 201,
			`{"id":10}`,
			map[string]any{"body": "lgtm"},
			nil, nil,
		},
		{
			"pr.read", `{"repo":"xcwds/site","number":7}`, "GET", "/repos/xcwds/site/pulls/7", 200,
			`{"number":7,"head":{"ref":"agent/job-a/fix","sha":"abc"},"base":{"ref":"main"},"user":{"login":"bot"}}`,
			nil,
			map[string]any{"head": "agent/job-a/fix", "base": "main", "head_sha": "abc"},
			nil,
		},
		{
			"pr.create", `{"repo":"xcwds/site","head":"agent/job-a/fix","base":"main","title":"Fix","body":"x","draft":true}`, "POST", "/repos/xcwds/site/pulls", 201,
			`{"number":8,"html_url":"https://github.com/p/8"}`,
			map[string]any{"head": "agent/job-a/fix", "base": "main", "title": "Fix", "body": "x", "draft": true},
			map[string]any{"number": float64(8)},
			nil,
		},
		{
			"pr.review.submit", `{"repo":"xcwds/site","number":7,"event":"COMMENT","body":"nit","comments":[{"path":"a.go","line":3,"body":"here"}]}`, "POST", "/repos/xcwds/site/pulls/7/reviews", 200,
			`{"id":5,"state":"COMMENTED"}`,
			map[string]any{"event": "COMMENT", "body": "nit"},
			map[string]any{"state": "COMMENTED"},
			func(t *testing.T, _ map[string]any, rec recorded) {
				cs, _ := rec.Body["comments"].([]any)
				if len(cs) != 1 {
					t.Errorf("review comments = %v", rec.Body["comments"])
				}
			},
		},
		{
			"pr.merge", `{"repo":"xcwds/site","number":7,"method":"squash","sha":"` + strings.Repeat("a", 40) + `"}`, "PUT", "/repos/xcwds/site/pulls/7/merge", 200,
			`{"sha":"def","merged":true}`,
			map[string]any{"merge_method": "squash", "sha": strings.Repeat("a", 40)},
			map[string]any{"merged": true},
			nil,
		},
		{
			"checks.read", `{"repo":"xcwds/site","ref":"main"}`, "GET", "/repos/xcwds/site/commits/main/check-runs", 200,
			`{"total_count":1,"check_runs":[{"name":"CI","status":"completed","conclusion":"success","output":{"text":"secret?"}}]}`,
			nil,
			map[string]any{"total": float64(1)},
			func(t *testing.T, got map[string]any, _ recorded) {
				if b, _ := json.Marshal(got); strings.Contains(string(b), "output") {
					t.Error("raw check output passed through")
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			f := newAPIFake(t)
			f.on(tc.method, tc.path, tc.status, tc.reply)
			res, err := execute(t, f, tc.action, tc.params)
			if err != nil {
				t.Fatal(err)
			}
			rec := f.last()
			if rec.Method != tc.method || rec.Path != tc.path || rec.Auth != "Bearer ghs_installtoken" {
				t.Errorf("request %s %s (auth %q)", rec.Method, rec.Path, rec.Auth)
			}
			for k, v := range tc.wantReq {
				if b1, b2 := mustJSON(rec.Body[k]), mustJSON(v); b1 != b2 {
					t.Errorf("request %s = %s, want %s", k, b1, b2)
				}
			}
			got := body(t, res)
			for k, v := range tc.wantBody {
				if mustJSON(got[k]) != mustJSON(v) {
					t.Errorf("result %s = %v, want %v", k, got[k], v)
				}
			}
			if res.UpstreamStatus != tc.status {
				t.Errorf("status = %d", res.UpstreamStatus)
			}
			// Curated results: no raw GitHub fields like owner or permissions.
			if b, _ := json.Marshal(got); strings.Contains(string(b), "permissions") || strings.Contains(string(b), "ghs_") {
				t.Errorf("result leaks raw fields: %s", b)
			}
			if tc.check != nil {
				tc.check(t, got, rec)
			}
		})
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestFileGet(t *testing.T) {
	f := newAPIFake(t)
	content := base64.StdEncoding.EncodeToString([]byte("package main\n"))
	f.on("GET", "/repos/xcwds/site/contents/cmd/main.go", 200, `{"type":"file","path":"cmd/main.go","sha":"s","size":13,"encoding":"base64","content":"`+content+`"}`)
	res, err := execute(t, f, "repo.file.get", `{"repo":"xcwds/site","path":"cmd/main.go","ref":"agent/job-a/fix"}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := body(t, res); got["content"] != "package main\n" || got["encoding"] != "utf-8" {
		t.Errorf("result = %v", got)
	}
	if q := f.last().Query; q != "ref=agent%2Fjob-a%2Ffix" {
		t.Errorf("query = %q", q)
	}

	f.on("GET", "/repos/xcwds/site/contents/bin", 200, `{"type":"file","path":"bin","sha":"s","size":3,"encoding":"base64","content":"`+base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe, 0x00})+`"}`)
	res, _ = execute(t, f, "repo.file.get", `{"repo":"xcwds/site","path":"bin"}`)
	if got := body(t, res); got["encoding"] != "base64" {
		t.Errorf("binary file = %v", got)
	}

	f.on("GET", "/repos/xcwds/site/contents/dir", 200, `[{"name":"a"}]`)
	if _, err := execute(t, f, "repo.file.get", `{"repo":"xcwds/site","path":"dir"}`); err == nil || !strings.Contains(err.Error(), "not a file") {
		t.Errorf("directory: %v", err)
	}
	f.on("GET", "/repos/xcwds/site/contents/big", 200, `{"type":"file","path":"big","sha":"s","size":5000000,"encoding":"none","content":""}`)
	if res, _ := execute(t, f, "repo.file.get", `{"repo":"xcwds/site","path":"big"}`); body(t, res)["too_large"] != true {
		t.Error("a large file was not flagged")
	}

	// Traversal is refused before any request.
	before := f.count()
	for _, p := range []string{`../../orgs/xcwds`, `a/../../x`, `a//b`, `./a`} {
		if _, err := execute(t, f, "repo.file.get", `{"repo":"xcwds/site","path":"`+p+`"}`); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}
	if f.count() != before {
		t.Error("a traversal path reached GitHub")
	}
	// A segment with special characters is escaped, not interpreted.
	f.on("GET", "/repos/xcwds/site/contents/a%3Fx=1", 200, `{"type":"file","path":"a?x=1","sha":"s","size":0,"encoding":"base64","content":""}`)
	if _, err := execute(t, f, "repo.file.get", `{"repo":"xcwds/site","path":"a?x=1"}`); err != nil {
		t.Errorf("escaped path: %v", err)
	}
}

func TestDiff(t *testing.T) {
	f := newAPIFake(t)
	f.on("GET", "/repos/xcwds/site/pulls/7", 200, "diff --git a/x b/x\n")
	res, err := execute(t, f, "pr.diff", `{"repo":"xcwds/site","number":7}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := body(t, res); got["diff"] != "diff --git a/x b/x\n" || got["truncated"] != false {
		t.Errorf("result = %v", got)
	}
	if f.last().Accept != "application/vnd.github.diff" {
		t.Errorf("accept = %q", f.last().Accept)
	}
}

func TestUpstreamErrors(t *testing.T) {
	f := newAPIFake(t)
	f.on("PUT", "/repos/xcwds/site/pulls/7/merge", 405, `{"message":"Pull Request is not mergeable"}`)
	res, err := execute(t, f, "pr.merge", `{"repo":"xcwds/site","number":7}`)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 405 || res.UpstreamStatus != 405 || !strings.Contains(err.Error(), "not mergeable") {
		t.Fatalf("err = %v, status %d", err, res.UpstreamStatus)
	}
	res, err = execute(t, f, "issue.read", `{"repo":"xcwds/site","number":99}`)
	if err == nil || res.UpstreamStatus != 404 {
		t.Errorf("404: %v %d", err, res.UpstreamStatus)
	}
}

// Repositories must arrive in canonical form, so policy and GitHub agree on
// which repository is meant.
func TestRepoNormalization(t *testing.T) {
	c, _ := New(Config{AppID: "1", InstallationID: 42, PrivateKeySecret: "k"}, secretMap{})
	reg, _ := connector.NewRegistry(c)
	for _, repo := range []string{
		"XCWDS/Site", "xcwds/Site", "xcwds/site/", "/xcwds/site", "xcwds/..", "xcwds/.hidden",
		"https://github.com/xcwds/site", "xcwds", "xcwds/site/extra", " xcwds/site", "xcwds/si te",
	} {
		if _, _, _, err := reg.Resolve("github.repo.read", json.RawMessage(`{"repo":`+mustJSON(repo)+`}`)); !errors.Is(err, connector.ErrInvalidParams) {
			t.Errorf("repo %q accepted", repo)
		}
	}
	if _, _, _, err := reg.Resolve("github.repo.read", json.RawMessage(`{"repo":"xcwds/site"}`)); err != nil {
		t.Errorf("canonical repo refused: %v", err)
	}
	// ".git" passes the schema's character set; Execute refuses it before
	// calling GitHub.
	f := newAPIFake(t)
	c2, _ := New(Config{AppID: "1", InstallationID: 42, PrivateKeySecret: "k", APIURL: f.srv.URL}, secretMap{})
	_, err := c2.Execute(ctx, cred, jobs.Job{}, connector.Action{Connector: "github", Name: "repo.read", Params: json.RawMessage(`{"repo":"xcwds/site.git"}`)})
	if err == nil || f.count() != 0 {
		t.Errorf("site.git: %v, %d requests", err, f.count())
	}
}

func TestBadParamsRefused(t *testing.T) {
	c, _ := New(Config{AppID: "1", InstallationID: 42, PrivateKeySecret: "k"}, secretMap{})
	reg, _ := connector.NewRegistry(c)
	for _, tc := range []struct{ action, params string }{
		{"pr.create", `{"repo":"xcwds/site","head":"evil:main","base":"main","title":"t"}`}, // cross-fork head
		{"pr.create", `{"repo":"xcwds/site","head":"/x","base":"main","title":"t"}`},
		{"pr.review.submit", `{"repo":"xcwds/site","number":1,"event":"DISMISS"}`},
		{"pr.merge", `{"repo":"xcwds/site","number":1,"method":"force"}`},
		{"pr.merge", `{"repo":"xcwds/site","number":0}`},
		{"issue.comment", `{"repo":"xcwds/site","number":1,"body":""}`},
		{"issue.comment", `{"repo":"xcwds/site","number":1,"body":"` + strings.Repeat("x", maxBody+1) + `"}`},
		{"checks.read", `{"repo":"xcwds/site","ref":"main; rm"}`},
	} {
		if _, _, _, err := reg.Resolve("github."+tc.action, json.RawMessage(tc.params)); !errors.Is(err, connector.ErrInvalidParams) {
			t.Errorf("%s %.60s accepted", tc.action, tc.params)
		}
	}
	f := newAPIFake(t)
	c2, _ := New(Config{AppID: "1", InstallationID: 42, PrivateKeySecret: "k", APIURL: f.srv.URL}, secretMap{})
	for _, ref := range []string{"a..b", "main/", "x.lock"} {
		if _, err := c2.Execute(ctx, cred, jobs.Job{}, connector.Action{Connector: "github", Name: "checks.read", Params: json.RawMessage(`{"repo":"xcwds/site","ref":"` + ref + `"}`)}); err == nil {
			t.Errorf("ref %q accepted", ref)
		}
	}
}

// The default policy, the pipeline and this connector together: the RFC's
// reviewer scenario at unit scale (the end-to-end version is #16).
func TestReviewerThroughThePipeline(t *testing.T) {
	gh := newFake(t)
	api := newAPIFake(t)
	// One server for both: token minting from the mint fake, actions from
	// the API fake.
	mux := http.NewServeMux()
	mux.Handle("/app/", gh.srv.Config.Handler)
	mux.Handle("/installation/", gh.srv.Config.Handler)
	mux.Handle("/repos/", api.srv.Config.Handler)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	api.on("POST", "/repos/xcwds/site/issues/7/comments", 201, `{"id":1}`)
	api.on("POST", "/repos/xcwds/site/pulls/7/reviews", 200, `{"id":2,"state":"APPROVED"}`)

	c, err := New(Config{AppID: "12345", InstallationID: 42, PrivateKeySecret: "github/app-key", APIURL: srv.URL}, secretMap{"github/app-key": pkcs1()})
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := connector.NewRegistry(c)
	pol, err := policy.LoadFS("defaults", policies.Defaults)
	if err != nil {
		t.Fatal(err)
	}
	if un := pol.Unmatched(reg.Actions()); len(un) == 0 || strings.Contains(strings.Join(un, " "), "github.pr.review.submit") {
		t.Logf("unmatched: %v", un) // git.* rules wait for #17
	}
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	logs := &bytes.Buffer{}
	logger := logging.New(logs, "json", slog.LevelInfo)
	pl := pipeline.New(reg, pol, audit.New(db, logger), connector.NewCache(), logger)
	p := jobs.Principal{SessionID: "ses-1", Job: jobs.Job{
		ID: "job-k3x9q2ma", Role: "reviewer", ExpiresAt: time.Now().Add(time.Hour),
		Grants: jobs.Grants{GitHub: &jobs.GitHubGrant{Repos: []string{"xcwds/site"}}},
	}}

	if _, err := pl.Run(ctx, p, "mcp", "github.pr.comment", json.RawMessage(`{"repo":"xcwds/site","number":7,"body":"looks good"}`)); err != nil {
		t.Fatalf("comment: %v", err)
	}
	before := api.count()
	_, err = pl.Run(ctx, p, "mcp", "github.pr.review.submit", json.RawMessage(`{"repo":"xcwds/site","number":7,"event":"APPROVE"}`))
	var denied *pipeline.Denied
	if !errors.As(err, &denied) || denied.Rule != "reviewer/never-approve" {
		t.Fatalf("approve: %v", err)
	}
	if api.count() != before {
		t.Fatal("the denied approve reached GitHub")
	}
	reqs, _, _ := gh.snapshot()
	if len(reqs) != 1 {
		t.Errorf("%d token mints, want 1", len(reqs))
	}
	if strings.Contains(logs.String(), "ghs_") {
		t.Error("a token reached the logs")
	}
	recs, _ := audit.Tail(ctx, db.Read(), audit.Filter{Limit: 10})
	for _, r := range recs {
		if strings.Contains(string(r.Params)+r.Error, "ghs_") {
			t.Errorf("a token reached the audit log: %+v", r)
		}
	}
}
