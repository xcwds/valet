package jobs

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/store"
	"github.com/xcwds/valet/internal/tokens"
)

var ctx = context.Background()

type fixture struct {
	dir string
	db  *store.Store
	svc *Service
	now time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{dir: filepath.Join(t.TempDir(), "data"), now: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
	db, err := store.Open(ctx, f.dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f.db = db
	f.svc = NewService(db, audit.New(db, logging.New(&bytes.Buffer{}, "json", slog.LevelError)))
	f.svc.now = func() time.Time { return f.now }
	return f
}

func (f *fixture) create(t *testing.T, req CreateRequest) (Job, string) {
	t.Helper()
	if req.CreatedBy == "" {
		req.CreatedBy = "admin:test"
	}
	j, tok, err := f.svc.Create(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	return j, tok
}

func (f *fixture) auditTrail(t *testing.T) []audit.Record {
	t.Helper()
	recs, err := audit.Tail(ctx, f.db.Read(), audit.Filter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func TestCreate(t *testing.T) {
	f := newFixture(t)
	j, tok := f.create(t, CreateRequest{Role: "implementer", Repos: []string{"XCWDS/Site", "xcwds/site", "xcwds/valet"}, TTL: 2 * time.Hour})
	if !ValidID(j.ID) || j.BranchPattern != "agent/"+j.ID+"/*" || j.State != StateActive {
		t.Errorf("job = %+v", j)
	}
	if got := strings.Join(j.Repos(), ","); got != "xcwds/site,xcwds/valet" {
		t.Errorf("repos = %s, want normalized and deduplicated", got)
	}
	if !j.ExpiresAt.Equal(f.now.Add(2 * time.Hour)) {
		t.Errorf("expires = %s", j.ExpiresAt)
	}
	if _, err := tokens.Parse(tokens.Session, tok); err != nil {
		t.Errorf("token %q is not a session token", tok)
	}
	got, err := f.svc.Get(ctx, j.ID)
	if err != nil || got.ID != j.ID || got.Role != "implementer" || got.CreatedBy != "admin:test" {
		t.Fatalf("Get = %+v, %v", got, err)
	}

	recs := f.auditTrail(t)
	if len(recs) != 1 || recs[0].Action != "job.create" || recs[0].JobID != j.ID || recs[0].SessionID == "" {
		t.Fatalf("audit = %+v", recs)
	}
	if strings.Contains(string(recs[0].Params), tok) {
		t.Error("token in the audit record")
	}
}

func TestTokenNotStored(t *testing.T) {
	f := newFixture(t)
	_, tok := f.create(t, CreateRequest{Role: "reviewer"})
	_ = f.db.Close()
	for _, suffix := range []string{"", "-wal"} {
		b, _ := os.ReadFile(filepath.Join(f.dir, store.FileName+suffix))
		if bytes.Contains(b, []byte(tok)) {
			t.Errorf("plaintext token in %s%s", store.FileName, suffix)
		}
	}
}

func TestCreateValidation(t *testing.T) {
	f := newFixture(t)
	many := make([]string, MaxRepos+1)
	for i := range many {
		many[i] = "o/r" + strings.Repeat("x", i)
	}
	bad := []CreateRequest{
		{Role: ""},
		{Role: "Reviewer"},
		{Role: "a b"},
		{Role: "-x"},
		{Role: "r", TTL: 30 * time.Second},
		{Role: "r", TTL: 25 * time.Hour},
		{Role: "r", TTL: -time.Hour},
		{Role: "r", Repos: []string{"noslash"}},
		{Role: "r", Repos: []string{"a/b/c"}},
		{Role: "r", Repos: []string{"https://github.com/a/b"}},
		{Role: "r", Repos: []string{"a/b.git"}},
		{Role: "r", Repos: []string{"a/.."}},
		{Role: "r", Repos: many},
	}
	for _, req := range bad {
		req.CreatedBy = "admin:test"
		if _, _, err := f.svc.Create(ctx, req); !errors.Is(err, ErrInvalid) {
			t.Errorf("Create(%+v) = %v, want ErrInvalid", req, err)
		}
	}
	if _, _, err := f.svc.Create(ctx, CreateRequest{Role: "r"}); !errors.Is(err, ErrInvalid) {
		t.Error("missing created_by accepted")
	}
	if n := len(f.auditTrail(t)); n != 0 {
		t.Errorf("%d audit records for refused creates", n)
	}
}

func TestAuthenticate(t *testing.T) {
	f := newFixture(t)
	j, tok := f.create(t, CreateRequest{Role: "reviewer", Repos: []string{"xcwds/site"}})
	p, err := f.svc.Authenticate(ctx, tok, audit.InterfaceMCP, "10.0.0.1")
	if err != nil || p.Job.ID != j.ID || p.SessionID == "" {
		t.Fatalf("Authenticate = %+v, %v", p, err)
	}
}

func lastDeny(t *testing.T, f *fixture) audit.Record {
	t.Helper()
	recs := f.auditTrail(t)
	r := recs[len(recs)-1]
	if r.Action != "session.authenticate" || r.Decision != audit.Deny {
		t.Fatalf("last audit = %+v, want a session.authenticate deny", r)
	}
	return r
}

func TestAuthenticateFailures(t *testing.T) {
	f := newFixture(t)
	_, tok := f.create(t, CreateRequest{Role: "reviewer"})
	admin, _, _ := tokens.New(tokens.Admin)
	other, _, _ := tokens.New(tokens.Session)

	cases := map[string]string{
		"":                   "missing token",
		"vlt_sess_nope":      "malformed token",
		admin:                "malformed token", // an admin token is never a session token
		other:                "unknown token",
		tok + "x":            "malformed token",
		strings.ToUpper(tok): "malformed token",
	}
	for in, reason := range cases {
		_, err := f.svc.Authenticate(ctx, in, audit.InterfaceGit, "10.0.0.1")
		if !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("Authenticate(%.20q) = %v", in, err)
			continue
		}
		r := lastDeny(t, f)
		if !strings.Contains(string(r.Params), reason) || r.Interface != audit.InterfaceGit {
			t.Errorf("Authenticate(%.20q): audit %s on %s, want %q", in, r.Params, r.Interface, reason)
		}
		if in != "" && strings.Contains(string(r.Params), in) {
			t.Errorf("token in the audit record")
		}
	}
}

func TestExpiry(t *testing.T) {
	f := newFixture(t)
	j, tok := f.create(t, CreateRequest{Role: "reviewer", TTL: time.Hour})
	f.now = f.now.Add(time.Hour - time.Second)
	if _, err := f.svc.Authenticate(ctx, tok, audit.InterfaceMCP, "10.0.0.1"); err != nil {
		t.Fatalf("a second before expiry: %v", err)
	}
	f.now = f.now.Add(time.Second)
	if _, err := f.svc.Authenticate(ctx, tok, audit.InterfaceMCP, "10.0.0.1"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("at expiry: %v", err)
	}
	r := lastDeny(t, f)
	if !strings.Contains(string(r.Params), "job expired") || r.JobID != j.ID {
		t.Errorf("audit = %+v", r)
	}
	got, _ := f.svc.Get(ctx, j.ID)
	if got.State != StateExpired {
		t.Errorf("state = %s, want expired", got.State)
	}
}

func TestRevoke(t *testing.T) {
	f := newFixture(t)
	j, tok := f.create(t, CreateRequest{Role: "reviewer"})
	if err := f.svc.Revoke(ctx, j.ID, "admin:test", "probing"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, tok, audit.InterfaceMCP, "10.0.0.1"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked session authenticated: %v", err)
	}
	if r := lastDeny(t, f); !strings.Contains(string(r.Params), "job revoked") {
		t.Errorf("audit = %s", r.Params)
	}
	got, _ := f.svc.Get(ctx, j.ID)
	if got.State != StateRevoked || got.RevokedAt.IsZero() {
		t.Errorf("job = %+v", got)
	}
	if err := f.svc.Revoke(ctx, j.ID, "admin:test", ""); !errors.Is(err, ErrNotActive) {
		t.Errorf("second revoke = %v, want ErrNotActive", err)
	}
	if err := f.svc.Revoke(ctx, "job-aaaaaaaa", "admin:test", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown revoke = %v, want ErrNotFound", err)
	}
	var revokes int
	for _, r := range f.auditTrail(t) {
		if r.Action == "job.revoke" {
			revokes++
			if !strings.Contains(string(r.Params), "probing") {
				t.Errorf("revoke reason missing: %s", r.Params)
			}
		}
	}
	if revokes != 1 {
		t.Errorf("%d job.revoke records, want 1", revokes)
	}
}

func TestListAndGet(t *testing.T) {
	f := newFixture(t)
	a, _ := f.create(t, CreateRequest{Role: "reviewer"})
	f.now = f.now.Add(time.Minute)
	b, _ := f.create(t, CreateRequest{Role: "implementer"})
	list, err := f.svc.List(ctx, 0)
	if err != nil || len(list) != 2 || list[0].ID != b.ID || list[1].ID != a.ID {
		t.Fatalf("List = %v, %v", list, err)
	}
	for _, id := range []string{"", "job-AAAAAAAA", "../x", "job-aaaaaaaa"} {
		if _, err := f.svc.Get(ctx, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%q) = %v", id, err)
		}
	}
}

func TestFailedAuthIsThrottled(t *testing.T) {
	f := newFixture(t)
	_, tok := f.create(t, CreateRequest{Role: "reviewer"})
	before := len(f.auditTrail(t))
	var unauth, throttled int
	for range 50 {
		_, err := f.svc.Authenticate(ctx, "vlt_sess_bogus", audit.InterfaceMCP, "10.0.0.66")
		switch {
		case errors.Is(err, ErrThrottled):
			throttled++
		case errors.Is(err, ErrUnauthenticated):
			unauth++
		}
	}
	if unauth != 10 || throttled != 40 {
		t.Errorf("%d unauthenticated, %d throttled; want 10 and 40", unauth, throttled)
	}
	recs := f.auditTrail(t)
	if got := len(recs) - before; got != 11 {
		t.Errorf("%d audit records for 50 failures, want 10 plus one throttle record", got)
	}
	if last := recs[len(recs)-1]; !strings.Contains(string(last.Params), "throttled") || !strings.Contains(string(last.Params), "10.0.0.66") {
		t.Errorf("throttle record = %s", last.Params)
	}
	// The flooding source's valid token still works, and other sources are untouched.
	if _, err := f.svc.Authenticate(ctx, tok, audit.InterfaceMCP, "10.0.0.66"); err != nil {
		t.Errorf("valid token from a throttled source: %v", err)
	}
	if _, err := f.svc.Authenticate(ctx, "vlt_sess_bogus", audit.InterfaceMCP, "10.0.0.67"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("another source: %v", err)
	}
}
