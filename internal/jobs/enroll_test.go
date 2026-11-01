package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xcwds/valet/internal/alert"
	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/logging"
)

type alertLog struct {
	mu  sync.Mutex
	got []alert.Alert
}

func (a *alertLog) Send(x alert.Alert) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.got = append(a.got, x)
}

func (a *alertLog) n() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.got)
}

func enrollFixture(t *testing.T) (*fixture, *alertLog) {
	t.Helper()
	f := newFixture(t)
	a := &alertLog{}
	f.svc.SetAlerter(a)
	return f, a
}

func (f *fixture) enrollJob(t *testing.T) (Job, Enrollment) {
	t.Helper()
	j, e, err := f.svc.CreateForEnrollment(ctx, CreateRequest{Role: "implementer", Repos: []string{"xcwds/site"}, CreatedBy: "admin:test"})
	if err != nil {
		t.Fatal(err)
	}
	return j, e
}

func (f *fixture) sessions(t *testing.T, jobID string) int {
	t.Helper()
	var n int
	if err := f.db.Read().QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE job_id = ?`, jobID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *fixture) enrollEvents(t *testing.T) []audit.Record {
	t.Helper()
	var out []audit.Record
	for _, r := range f.auditTrail(t) {
		if r.Action == "session.enroll" {
			out = append(out, r)
		}
	}
	return out
}

func TestFirstUse(t *testing.T) {
	f, alerts := enrollFixture(t)
	j, e := f.enrollJob(t)
	if !strings.HasPrefix(e.Code, "vlt_enroll_") || !e.ExpiresAt.Equal(f.now.Add(DefaultCodeTTL)) {
		t.Fatalf("enrollment = %+v", e)
	}
	if f.sessions(t, j.ID) != 0 {
		t.Fatal("a job created for enrollment already has a session")
	}
	body, err := f.svc.Enroll(ctx, e.Code, "172.20.0.5")
	if err != nil {
		t.Fatal(err)
	}
	var resp EnrollResponse
	if err := json.Unmarshal(body, &resp); err != nil || resp.JobID != j.ID || !resp.ExpiresAt.Equal(j.ExpiresAt) {
		t.Fatalf("response = %s (%v)", body, err)
	}
	p, err := f.svc.Authenticate(ctx, resp.SessionToken, audit.InterfaceMCP, "x")
	if err != nil || p.Job.ID != j.ID {
		t.Fatalf("the issued token doesn't authenticate: %v", err)
	}
	ev := f.enrollEvents(t)
	if len(ev) != 1 || ev[0].Decision != audit.Allow || ev[0].SessionID != p.SessionID || ev[0].Interface != audit.InterfaceEnroll ||
		strings.Contains(string(ev[0].Params), "replay") {
		t.Errorf("audit = %+v", ev)
	}
	if alerts.n() != 0 {
		t.Error("first use alerted")
	}
}

func TestConcurrentFirstUsesShareOneSession(t *testing.T) {
	f, alerts := enrollFixture(t)
	j, e := f.enrollJob(t)
	n := 1 + DefaultMaxReplays
	bodies := make([][]byte, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() { defer wg.Done(); bodies[i], errs[i] = f.svc.Enroll(ctx, e.Code, "172.20.0.5") }()
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil || !bytes.Equal(bodies[i], bodies[0]) {
			t.Fatalf("request %d: %v, %s vs %s", i, errs[i], bodies[i], bodies[0])
		}
	}
	if s := f.sessions(t, j.ID); s != 1 {
		t.Errorf("%d sessions, want 1", s)
	}
	replays := 0
	for _, r := range f.enrollEvents(t) {
		if strings.Contains(string(r.Params), `"replay":true`) {
			replays++
		}
	}
	if replays != n-1 || alerts.n() != 0 {
		t.Errorf("%d replays audited, %d alerts", replays, alerts.n())
	}
}

func TestReplayWindow(t *testing.T) {
	f, alerts := enrollFixture(t)
	j, e := f.enrollJob(t)
	first, err := f.svc.Enroll(ctx, e.Code, "a")
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(30 * time.Second)
	again, err := f.svc.Enroll(ctx, e.Code, "a")
	if err != nil || !bytes.Equal(again, first) {
		t.Fatalf("replay: %v %s", err, again)
	}
	if f.sessions(t, j.ID) != 1 || alerts.n() != 0 {
		t.Errorf("a replay made a session or an alert")
	}
	// Past the window: refused, audited and alerted.
	f.now = f.now.Add(DefaultReplayWindow)
	if _, err := f.svc.Enroll(ctx, e.Code, "a"); !errors.Is(err, ErrEnrollRefused) {
		t.Fatalf("after the window: %v", err)
	}
	ev := f.enrollEvents(t)
	last := ev[len(ev)-1]
	if last.Decision != audit.Deny || !strings.Contains(last.Error, "repeat window over") || alerts.n() != 1 || !alerts.got[0].RuleAlert {
		t.Errorf("audit = %+v, alerts = %d", last, alerts.n())
	}
}

func TestReplayCap(t *testing.T) {
	f, alerts := enrollFixture(t)
	_, e := f.enrollJob(t)
	if _, err := f.svc.Enroll(ctx, e.Code, "a"); err != nil {
		t.Fatal(err)
	}
	for i := range DefaultMaxReplays {
		if _, err := f.svc.Enroll(ctx, e.Code, "a"); err != nil {
			t.Fatalf("replay %d: %v", i+1, err)
		}
	}
	if _, err := f.svc.Enroll(ctx, e.Code, "a"); !errors.Is(err, ErrEnrollRefused) || alerts.n() != 1 {
		t.Errorf("past the cap: %v, %d alerts", err, alerts.n())
	}
}

func TestRestartEndsTheWindow(t *testing.T) {
	f, alerts := enrollFixture(t)
	_, e := f.enrollJob(t)
	if _, err := f.svc.Enroll(ctx, e.Code, "a"); err != nil {
		t.Fatal(err)
	}
	// A restarted valetd: same database, nothing in memory.
	restarted := NewService(f.db, audit.New(f.db, logging.New(&bytes.Buffer{}, "json", slog.LevelError)))
	restarted.now = func() time.Time { return f.now }
	restarted.SetAlerter(alerts)
	if _, err := restarted.Enroll(ctx, e.Code, "a"); !errors.Is(err, ErrEnrollRefused) || alerts.n() != 1 {
		t.Errorf("after a restart: %v, %d alerts", err, alerts.n())
	}
}

func TestExpiredUnknownAndMalformedCodes(t *testing.T) {
	f, alerts := enrollFixture(t)
	_, e := f.enrollJob(t)
	f.now = f.now.Add(DefaultCodeTTL)
	for name, code := range map[string]string{
		"expired":   e.Code,
		"unknown":   "vlt_enroll_" + strings.Repeat("a", 52),
		"malformed": "hunter2",
		"session":   "vlt_sess_" + strings.Repeat("a", 52),
		"empty":     "",
	} {
		if _, err := f.svc.Enroll(ctx, code, "b"); !errors.Is(err, ErrEnrollRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if alerts.n() != 5 {
		t.Errorf("%d alerts, want 5", alerts.n())
	}
	ev := f.enrollEvents(t)
	reasons := map[string]bool{}
	for _, r := range ev {
		reasons[r.Error] = true
	}
	for _, want := range []string{"code expired", "unknown code", "malformed code"} {
		if !reasons[want] {
			t.Errorf("no audit record with reason %q: %v", want, reasons)
		}
	}
}

func TestRevokedJob(t *testing.T) {
	f, _ := enrollFixture(t)
	// Revoked before first use.
	j, e := f.enrollJob(t)
	if err := f.svc.Revoke(ctx, j.ID, "admin:test", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Enroll(ctx, e.Code, "c"); !errors.Is(err, ErrEnrollRefused) {
		t.Errorf("revoked before use: %v", err)
	}
	// Revoked inside the window.
	j2, e2 := f.enrollJob(t)
	if _, err := f.svc.Enroll(ctx, e2.Code, "c"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Revoke(ctx, j2.ID, "admin:test", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Enroll(ctx, e2.Code, "c"); !errors.Is(err, ErrEnrollRefused) {
		t.Errorf("revoked during the window: %v", err)
	}
	ev := f.enrollEvents(t)
	if last := ev[len(ev)-1]; last.Error != "job revoked" {
		t.Errorf("reason = %q", last.Error)
	}
	f.svc.replayMu.Lock()
	defer f.svc.replayMu.Unlock()
	if len(f.svc.replays) != 0 {
		t.Error("a revoked job's token is still held in memory")
	}
}

func TestReenroll(t *testing.T) {
	f, _ := enrollFixture(t)
	j, e := f.enrollJob(t)
	body, err := f.svc.Enroll(ctx, e.Code, "d")
	if err != nil {
		t.Fatal(err)
	}
	var old EnrollResponse
	_ = json.Unmarshal(body, &old)
	var closed []string
	f.svc.OnSessionsRevoked(func(_ context.Context, id string) { closed = append(closed, id) })

	e2, err := f.svc.Reenroll(ctx, j.ID, "admin:test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, old.SessionToken, audit.InterfaceMCP, "d"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("the old session survived re-enrollment: %v", err)
	}
	if _, err := f.svc.Enroll(ctx, e.Code, "d"); !errors.Is(err, ErrEnrollRefused) {
		t.Errorf("the old code still works: %v", err)
	}
	body, err = f.svc.Enroll(ctx, e2.Code, "d")
	if err != nil {
		t.Fatal(err)
	}
	var fresh EnrollResponse
	_ = json.Unmarshal(body, &fresh)
	if fresh.SessionToken == old.SessionToken || fresh.JobID != j.ID {
		t.Errorf("new session = %+v", fresh)
	}
	if _, err := f.svc.Authenticate(ctx, fresh.SessionToken, audit.InterfaceMCP, "d"); err != nil {
		t.Errorf("the new session doesn't work: %v", err)
	}
	if len(closed) != 1 || closed[0] != j.ID {
		t.Errorf("OnSessionsRevoked = %v", closed)
	}
	if err := f.svc.Revoke(ctx, j.ID, "admin:test", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Reenroll(ctx, j.ID, "admin:test"); !errors.Is(err, ErrNotActive) {
		t.Errorf("re-enrolling a revoked job: %v", err)
	}
}

func TestZeroWindowRefusesRetries(t *testing.T) {
	f, _ := enrollFixture(t)
	if err := f.svc.SetEnrollConfig(EnrollConfig{CodeTTL: time.Minute, ReplayWindow: 0, MaxReplays: 5}); err != nil {
		t.Fatal(err)
	}
	_, e := f.enrollJob(t)
	if _, err := f.svc.Enroll(ctx, e.Code, "e"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Enroll(ctx, e.Code, "e"); !errors.Is(err, ErrEnrollRefused) {
		t.Errorf("retry with no window: %v", err)
	}
}

func TestEnrollConfigBounds(t *testing.T) {
	for _, c := range []EnrollConfig{
		{CodeTTL: 0, ReplayWindow: time.Minute, MaxReplays: 1},
		{CodeTTL: time.Minute, ReplayWindow: 6 * time.Minute, MaxReplays: 1},
		{CodeTTL: time.Minute, ReplayWindow: -time.Second, MaxReplays: 1},
		{CodeTTL: time.Minute, ReplayWindow: time.Minute, MaxReplays: 100},
		{CodeTTL: 48 * time.Hour, ReplayWindow: time.Minute, MaxReplays: 1},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
}

func TestBadCodesAreThrottled(t *testing.T) {
	f, _ := enrollFixture(t)
	var refused, throttled int
	for range 30 {
		switch _, err := f.svc.Enroll(ctx, "vlt_enroll_"+strings.Repeat("z", 52), "10.9.9.9"); {
		case errors.Is(err, ErrThrottled):
			throttled++
		case errors.Is(err, ErrEnrollRefused):
			refused++
		}
	}
	if refused != 10 || throttled != 20 {
		t.Errorf("%d refused, %d throttled", refused, throttled)
	}
}

// The database (and its WAL) holds only the token's hash.
func TestTokenNeverStored(t *testing.T) {
	f, _ := enrollFixture(t)
	_, e := f.enrollJob(t)
	body, err := f.svc.Enroll(ctx, e.Code, "f")
	if err != nil {
		t.Fatal(err)
	}
	var resp EnrollResponse
	_ = json.Unmarshal(body, &resp)
	matches, _ := filepath.Glob(filepath.Join(f.dir, "valet.db*"))
	if len(matches) == 0 {
		t.Fatal("no database files found")
	}
	for _, m := range matches {
		b, _ := os.ReadFile(m)
		if bytes.Contains(b, []byte(resp.SessionToken)) || bytes.Contains(b, []byte(e.Code)) {
			t.Errorf("%s holds a plaintext token or code", m)
		}
	}
}

func TestEnrollHandler(t *testing.T) {
	f, _ := enrollFixture(t)
	_, e := f.enrollJob(t)
	h := f.svc.EnrollHandler()
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", EnrollPath, strings.NewReader(body))
		r.RemoteAddr = "172.20.0.9:4000"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	a := post(`{"code":"` + e.Code + `"}`)
	b := post(`{"code":"` + e.Code + `"}`)
	if a.Code != 200 || b.Code != 200 || a.Body.String() != b.Body.String() || a.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %d %q %q", a.Code, b.Code, a.Body, b.Body)
	}
	for _, body := range []string{`{"code":"vlt_enroll_nope"}`, `not json`, ``} {
		if w := post(body); w.Code != http.StatusForbidden || w.Body.String() != `{"error":"enrollment refused"}` {
			t.Errorf("%q: %d %s", body, w.Code, w.Body)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", EnrollPath, nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", w.Code)
	}
}

// Dropping a failed first use's entry must not drop a newer one.
func TestDropReplayIfOnlyDropsItsOwnEntry(t *testing.T) {
	f, _ := enrollFixture(t)
	old := f.svc.putReplay("enr-x", "job-a", []byte("old"), f.now)
	newer := f.svc.putReplay("enr-x", "job-a", []byte("new"), f.now)
	f.svc.dropReplayIf("enr-x", old)
	if body, _, reason := f.svc.takeReplay("enr-x", f.now); reason != "" || string(body) != "new" {
		t.Fatalf("the newer entry was dropped: %q %q", body, reason)
	}
	f.svc.dropReplayIf("enr-x", newer)
	if _, _, reason := f.svc.takeReplay("enr-x", f.now); reason == "" {
		t.Error("the entry survived its own drop")
	}
}
