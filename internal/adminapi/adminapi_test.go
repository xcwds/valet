package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/jobs"
	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/operator"
	"github.com/xcwds/valet/internal/secrets"
	"github.com/xcwds/valet/internal/store"
)

var ctx = context.Background()

type fixture struct {
	srv   *httptest.Server
	token string
	db    *store.Store
	logs  *bytes.Buffer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	db, err := store.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	logs := &bytes.Buffer{}
	log := logging.New(logs, "json", slog.LevelInfo)
	alog := audit.New(db, log)
	enc, _ := secrets.NewMasterKey()
	key, _ := secrets.ParseMasterKey(enc)
	sec, err := secrets.Open(ctx, db, key, alog)
	if err != nil {
		t.Fatal(err)
	}
	ops := operator.NewService(db, alog)
	path, err := ops.Bootstrap(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	srv := httptest.NewServer(Handler(Deps{Jobs: jobs.NewService(db, alog), Operator: ops, Secrets: sec, AuditDB: db.Read(), Log: log}))
	t.Cleanup(srv.Close)
	return &fixture{srv: srv, token: strings.TrimSpace(string(b)), db: db, logs: logs}
}

// result is a response, already read and closed.
type result struct {
	StatusCode int
	Header     http.Header
}

func (f *fixture) do(t *testing.T, method, path, contentType, body string) (result, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, method, f.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+f.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return result{resp.StatusCode, resp.Header}, string(b)
}

func TestCreateJob(t *testing.T) {
	f := newFixture(t)
	resp, body := f.do(t, "POST", "/api/jobs", "application/json", `{"role":"reviewer","repos":["xcwds/site"],"ttl":"30m"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("a response holding a token is cacheable")
	}
	var got struct {
		Job   jobs.Job `json:"job"`
		Token string   `json:"token"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil || got.Job.CreatedBy != "admin:bootstrap" || got.Job.TTL != "30m0s" {
		t.Fatalf("%s (%v)", body, err)
	}
}

func TestBadRequests(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name, method, path, ct, body string
		want                         int
	}{
		{"no content type", "POST", "/api/jobs", "", `{"role":"r"}`, 415},
		{"form content type", "POST", "/api/jobs", "application/x-www-form-urlencoded", `role=r`, 415},
		{"unknown field", "POST", "/api/jobs", "application/json", `{"role":"r","admin":true}`, 400},
		{"not JSON", "POST", "/api/jobs", "application/json", `{`, 400},
		{"bad role", "POST", "/api/jobs", "application/json", `{"role":"Root"}`, 400},
		{"bad ttl", "POST", "/api/jobs", "application/json", `{"role":"r","ttl":"forever"}`, 400},
		{"ttl too long", "POST", "/api/jobs", "application/json", `{"role":"r","ttl":"48h"}`, 400},
		{"huge body", "POST", "/api/jobs", "application/json", `{"role":"r","repos":["` + strings.Repeat("a", 70<<10) + `"]}`, 400},
		{"unknown job", "GET", "/api/jobs/job-aaaaaaaa", "", "", 404},
		{"malformed job id", "GET", "/api/jobs/nope", "", "", 404},
		{"revoke unknown", "POST", "/api/jobs/job-aaaaaaaa/revoke", "", "", 404},
		{"secret double slash", "PUT", "/api/secrets/a//b", "application/octet-stream", "v", 400},
		{"secret dot dot", "PUT", "/api/secrets/a/%2e%2e/b", "application/octet-stream", "v", 400},
		{"secret encoded slash", "PUT", "/api/secrets/a%2fb", "application/octet-stream", "v", 400},
		{"secret uppercase", "PUT", "/api/secrets/Upper", "application/octet-stream", "v", 400},
		{"secret empty", "PUT", "/api/secrets/x", "application/octet-stream", "", 400},
		{"secret too big", "PUT", "/api/secrets/x", "application/octet-stream", strings.Repeat("v", secrets.MaxSecretSize+1), 413},
		{"delete missing secret", "DELETE", "/api/secrets/nope", "", "", 404},
		{"wrong method", "DELETE", "/api/jobs", "", "", 405},
	}
	for _, c := range cases {
		resp, body := f.do(t, c.method, c.path, c.ct, c.body)
		if resp.StatusCode != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, resp.StatusCode, body, c.want)
		}
	}
	var n int
	_ = f.db.Read().QueryRow(`SELECT (SELECT count(*) FROM jobs) + (SELECT count(*) FROM secrets)`).Scan(&n)
	if n != 0 {
		t.Errorf("%d jobs or secrets created by bad requests", n)
	}
}

func TestRevokeConflict(t *testing.T) {
	f := newFixture(t)
	_, body := f.do(t, "POST", "/api/jobs", "application/json", `{"role":"r"}`)
	var got struct{ Job jobs.Job }
	_ = json.Unmarshal([]byte(body), &got)
	if resp, b := f.do(t, "POST", "/api/jobs/"+got.Job.ID+"/revoke", "", ""); resp.StatusCode != 204 {
		t.Fatalf("revoke: %d %s", resp.StatusCode, b)
	}
	if resp, _ := f.do(t, "POST", "/api/jobs/"+got.Job.ID+"/revoke", "", ""); resp.StatusCode != 409 {
		t.Errorf("second revoke: %d, want 409", resp.StatusCode)
	}
}

func TestSecretsAndAudit(t *testing.T) {
	f := newFixture(t)
	if resp, b := f.do(t, "PUT", "/api/secrets/github/app-key", "application/octet-stream", "pem-bytes"); resp.StatusCode != 204 {
		t.Fatalf("put: %d %s", resp.StatusCode, b)
	}
	_, body := f.do(t, "GET", "/api/secrets", "", "")
	if !strings.Contains(body, "github/app-key") || strings.Contains(body, "pem-bytes") {
		t.Errorf("list = %s", body)
	}
	_, body = f.do(t, "GET", "/api/audit?limit=100", "", "")
	if !strings.Contains(body, `"secret.put"`) || strings.Contains(body, "pem-bytes") {
		t.Errorf("audit = %s", body)
	}
}

func TestInternalErrorsDoNotLeak(t *testing.T) {
	f := newFixture(t)
	// Break the database under the API: every handler now fails internally.
	if err := f.db.Read().Close(); err != nil {
		t.Fatal(err)
	}
	resp, body := f.do(t, "GET", "/api/audit", "", "")
	if resp.StatusCode != 500 && resp.StatusCode != 401 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if strings.Contains(body, "sql") || strings.Contains(body, "database") || strings.Contains(body, "/") {
		t.Errorf("internal detail in the response: %s", body)
	}
}
