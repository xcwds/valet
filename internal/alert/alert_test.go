package alert

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/xcwds/valet/internal/secrets"
)

type received struct {
	Headers http.Header
	Body    string
}

type sink struct {
	mu     sync.Mutex
	got    []received
	status int
	delay  time.Duration
	srv    *httptest.Server
}

func newSink(t *testing.T) *sink {
	s := &sink{status: 200}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		delay, status := s.delay, s.status
		s.mu.Unlock()
		// Read the body first: the server notices a client hang-up (and
		// cancels r.Context) only once the body is consumed.
		b, _ := io.ReadAll(r.Body)
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		s.mu.Lock()
		s.got = append(s.got, received{r.Header.Clone(), string(b)})
		s.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *sink) received() []received {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]received(nil), s.got...)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type secretMap map[string]string

func (m secretMap) Get(_ context.Context, name string) (secrets.Secret, error) {
	v, ok := m[name]
	if !ok {
		return secrets.Secret{}, secrets.ErrNotFound
	}
	return secrets.NewSecret([]byte(v)), nil
}

func start(t *testing.T, opts Options, ns ...Notifier) *Dispatcher {
	t.Helper()
	d := New(opts, slog.New(slog.NewTextHandler(io.Discard, nil)), ns...)
	d.backoff = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return d
}

func deny(job string) Alert {
	return Alert{
		JobID: job, Role: "reviewer", Action: "github.pr.review.submit", Decision: "deny",
		Rule: "reviewer/never-approve", Reason: "a reviewer agent may not approve",
		Params: json.RawMessage(`{"event":"APPROVE","number":7,"repo":"xcwds/site","token":"[redacted]"}`), AuditSeq: 42, RuleAlert: true,
	}
}

func TestNtfyMessage(t *testing.T) {
	s := newSink(t)
	n, err := NewNtfy(s.srv.URL+"/valet", "ntfy/token", secretMap{"ntfy/token": "tk_123"})
	if err != nil {
		t.Fatal(err)
	}
	d := start(t, Options{LinkBase: "https://valet.example/"}, n)
	d.Send(deny("job-aaaaaaaa"))
	waitFor(t, func() bool { return len(s.received()) == 1 })
	got := s.received()[0]
	if got.Headers.Get("Title") != "Denied github.pr.review.submit (job-aaaaaaaa, reviewer)" {
		t.Errorf("title = %q", got.Headers.Get("Title"))
	}
	if got.Headers.Get("Priority") != "high" || got.Headers.Get("Click") != "https://valet.example/audit/42" || got.Headers.Get("Authorization") != "Bearer tk_123" {
		t.Errorf("headers = %v", got.Headers)
	}
	for _, want := range []string{"rule: reviewer/never-approve", "reason: a reviewer agent may not approve", `"event":"APPROVE"`, "audit: #42", "[redacted]"} {
		if !strings.Contains(got.Body, want) {
			t.Errorf("body missing %q:\n%s", want, got.Body)
		}
	}
}

func TestWhichDecisionsAlert(t *testing.T) {
	plainDeny := deny("job-a")
	plainDeny.RuleAlert = false
	allowAlert := deny("job-b")
	allowAlert.Decision = "allow"
	allowPlain := allowAlert
	allowPlain.RuleAlert = false

	for _, tc := range []struct {
		onDeny string
		a      Alert
		want   bool
	}{
		{DenyAll, plainDeny, true},
		{DenyAlertRulesOnly, plainDeny, false},
		{DenyAlertRulesOnly, deny("job-c"), true},
		{DenyAll, allowAlert, true},
		{DenyAll, allowPlain, false},
	} {
		d := New(Options{OnDeny: tc.onDeny}, nil)
		if got := d.Wants(tc.a.Decision, tc.a.RuleAlert); got != tc.want {
			t.Errorf("%s %s alert=%v: %v, want %v", tc.onDeny, tc.a.Decision, tc.a.RuleAlert, got, tc.want)
		}
	}
}

func TestCoalescesAProbingJob(t *testing.T) {
	s := newSink(t)
	n, _ := NewNtfy(s.srv.URL, "", nil)
	d := start(t, Options{PerJob: 3, Window: 200 * time.Millisecond}, n)
	for range 20 {
		d.Send(deny("job-flood"))
	}
	d.Send(deny("job-other"))
	waitFor(t, func() bool { return len(s.received()) >= 5 })
	time.Sleep(50 * time.Millisecond)
	got := s.received()
	var flood, other int
	var summary string
	for _, r := range got {
		if strings.Contains(r.Headers.Get("Title"), "job-flood") {
			flood++
			if strings.Contains(r.Body, "more for this job") {
				summary = r.Body
			}
		} else {
			other++
		}
	}
	if flood != 4 || other != 1 {
		t.Errorf("flood %d, other %d; want 3 + 1 summary, and 1", flood, other)
	}
	if !strings.Contains(summary, "+16 more") {
		t.Errorf("summary = %q", summary)
	}
}

func TestSlowNotifierNeverBlocks(t *testing.T) {
	s := newSink(t)
	s.delay = time.Hour
	n, _ := NewNtfy(s.srv.URL, "", nil)
	d := start(t, Options{Queue: 4, Timeout: 50 * time.Millisecond, Attempts: 1}, n)
	begin := time.Now()
	for range 100 {
		d.Send(deny("job-aaaaaaaa"))
	}
	if took := time.Since(begin); took > 100*time.Millisecond {
		t.Fatalf("Send blocked for %s", took)
	}
	waitFor(t, func() bool { _, _, dropped := d.Stats(); return dropped > 0 })
}

func TestRetriesThenCountsFailure(t *testing.T) {
	s := newSink(t)
	s.status = 500
	n, _ := NewNtfy(s.srv.URL, "", nil)
	d := start(t, Options{Attempts: 3}, n)
	d.Send(deny("job-aaaaaaaa"))
	waitFor(t, func() bool { _, failed, _ := d.Stats(); return failed == 1 })
	if got := len(s.received()); got != 3 {
		t.Errorf("%d attempts, want 3", got)
	}
}

func TestWebhook(t *testing.T) {
	s := newSink(t)
	w, err := NewWebhook(s.srv.URL, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	d := start(t, Options{}, w)
	d.Send(deny("job-aaaaaaaa"))
	waitFor(t, func() bool { return len(s.received()) == 1 })
	var a Alert
	if err := json.Unmarshal([]byte(s.received()[0].Body), &a); err != nil || a.Rule != "reviewer/never-approve" || a.AuditSeq != 42 {
		t.Errorf("%+v %v", a, err)
	}
}

func TestDrainOnShutdown(t *testing.T) {
	s := newSink(t)
	n, _ := NewNtfy(s.srv.URL, "", nil)
	d := New(Options{}, slog.New(slog.NewTextHandler(io.Discard, nil)), n)
	ctx, cancel := context.WithCancel(context.Background())
	d.Send(deny("job-aaaaaaaa"))
	cancel()
	d.Run(ctx) // returns after draining
	if len(s.received()) != 1 {
		t.Error("a queued alert was lost at shutdown")
	}
}

func TestURLValidation(t *testing.T) {
	for _, u := range []string{"", "ntfy.sh/topic", "ftp://x", "https://user:pw@ntfy.sh/t"} {
		if _, err := NewNtfy(u, "", nil); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	if _, err := NewNtfy("http://ntfy.lan/valet", "", nil); err != nil {
		t.Errorf("a LAN ntfy over http refused: %v", err)
	}
}

func TestNoNotifiersNoWork(_ *testing.T) {
	var d *Dispatcher
	d.Send(deny("x")) // nil dispatcher is a no-op
	New(Options{}, nil).Send(deny("x"))
}

func TestShutdownFlushesSummaries(t *testing.T) {
	s := newSink(t)
	n, _ := NewNtfy(s.srv.URL, "", nil)
	d := New(Options{PerJob: 1, Window: time.Hour}, slog.New(slog.NewTextHandler(io.Discard, nil)), n)
	for range 5 {
		d.Send(deny("job-aaaaaaaa"))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.Run(ctx)
	got := s.received()
	if len(got) != 2 || !strings.Contains(got[1].Body, "+3 more") {
		t.Errorf("got %d messages; the held-back burst must be summarized at shutdown", len(got))
	}
}

func TestBodyTruncatesOnARuneBoundary(t *testing.T) {
	a := deny("job-a")
	a.Params = json.RawMessage(`{"t":"` + strings.Repeat("é", 400) + `"}`)
	b := a.Body()
	if !utf8.ValidString(b) || !strings.Contains(b, "…") {
		t.Errorf("body = %q", b)
	}
}

func TestHostileActionNameStillAlerts(t *testing.T) {
	s := newSink(t)
	n, _ := NewNtfy(s.srv.URL, "", nil)
	d := start(t, Options{}, n)
	a := deny("job-aaaaaaaa")
	a.Action = "x\r\nX-Injected: 1 " + strings.Repeat("é", 300)
	d.Send(a)
	waitFor(t, func() bool { return len(s.received()) == 1 })
	h := s.received()[0].Headers
	if h.Get("X-Injected") != "" || !strings.HasPrefix(h.Get("Title"), "Denied x??X-Injected") || len(h.Get("Title")) > 200 {
		t.Errorf("title = %q", h.Get("Title"))
	}
}
