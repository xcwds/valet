// Package alert tells the operator about denials and rules marked alert:
// true (RFC Policy engine, Alerts), on their phone via ntfy or any webhook.
//
// Delivery never touches the request path: Send only enqueues, a worker
// delivers with retries, and a full queue drops (and counts) rather than
// waits. Alerts are coalesced per job, so a probing agent can't flood the
// operator's phone. Params come from the audit record, already redacted and
// truncated.
package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// OnDeny settings.
const (
	DenyAll            = "all"              // every deny alerts
	DenyAlertRulesOnly = "alert_rules_only" // only rules marked alert: true
)

// Alert is one decision worth telling the operator about.
type Alert struct {
	Time      time.Time       `json:"time"`
	JobID     string          `json:"job_id"`
	Role      string          `json:"role"`
	Action    string          `json:"action"`
	Decision  string          `json:"decision"`
	Rule      string          `json:"rule"`
	Reason    string          `json:"reason"`
	Params    json.RawMessage `json:"params,omitempty"` // as audited: redacted, truncated
	AuditSeq  int64           `json:"audit_seq"`
	RuleAlert bool            `json:"rule_alert"` // the rule asked for it
	Link      string          `json:"link,omitempty"`
	// Suppressed counts alerts for this job coalesced into this one.
	Suppressed int `json:"suppressed,omitempty"`
}

// Title is a one-line summary.
func (a Alert) Title() string {
	verb := map[string]string{"deny": "Denied", "require_approval": "Needs approval", "allow": "Allowed"}[a.Decision]
	if verb == "" {
		verb = a.Decision
	}
	return headerSafe(fmt.Sprintf("%s %s (%s, %s)", verb, a.Action, a.JobID, a.Role), 200)
}

// headerSafe keeps printable ASCII and caps the length, so an agent-chosen
// string (an unknown action name) can't make the header invalid and
// suppress its own alert.
func headerSafe(s string, limit int) string {
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	if len(b) > limit {
		b = append(b[:limit-3], "..."...)
	}
	return string(b)
}

// Body is the message text.
func (a Alert) Body() string {
	var b strings.Builder
	if a.Rule != "" {
		fmt.Fprintf(&b, "rule: %s\n", a.Rule)
	}
	if a.Reason != "" {
		fmt.Fprintf(&b, "reason: %s\n", a.Reason)
	}
	if len(a.Params) > 0 && string(a.Params) != "{}" {
		p := string(a.Params)
		if len(p) > 300 {
			cut := 300
			for cut > 0 && !utf8.RuneStart(p[cut]) {
				cut--
			}
			p = p[:cut] + "…"
		}
		fmt.Fprintf(&b, "params: %s\n", p)
	}
	fmt.Fprintf(&b, "audit: #%d", a.AuditSeq)
	if a.Suppressed > 0 {
		fmt.Fprintf(&b, "\n(+%d more for this job not sent separately)", a.Suppressed)
	}
	return b.String()
}

// Notifier delivers alerts somewhere.
type Notifier interface {
	Name() string
	Notify(ctx context.Context, a Alert) error
}

// Options configure a Dispatcher.
type Options struct {
	OnDeny   string        // DenyAll (default) or DenyAlertRulesOnly
	LinkBase string        // admin UI base URL for links to the audit entry; optional
	PerJob   int           // alerts per job per Window before coalescing (default 5)
	Window   time.Duration // default 10 minutes
	Queue    int           // default 256
	Attempts int           // delivery attempts per notifier (default 3)
	Timeout  time.Duration // per attempt (default 10 s)
}

// Dispatcher queues alerts and delivers them in the background.
type Dispatcher struct {
	opts      Options
	notifiers []Notifier
	queue     chan Alert
	log       *slog.Logger
	now       func() time.Time
	backoff   time.Duration

	mu   sync.Mutex
	jobs map[string]*window

	dropped, failed, sent atomic.Int64
}

type window struct {
	start      time.Time
	n          int
	suppressed int
	last       Alert
}

// New returns a Dispatcher. Call Run to start delivering.
func New(opts Options, log *slog.Logger, notifiers ...Notifier) *Dispatcher {
	if opts.OnDeny == "" {
		opts.OnDeny = DenyAll
	}
	if opts.PerJob <= 0 {
		opts.PerJob = 5
	}
	if opts.Window <= 0 {
		opts.Window = 10 * time.Minute
	}
	if opts.Queue <= 0 {
		opts.Queue = 256
	}
	if opts.Attempts <= 0 {
		opts.Attempts = 3
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	return &Dispatcher{
		opts: opts, notifiers: notifiers, queue: make(chan Alert, opts.Queue), log: log,
		now: time.Now, backoff: time.Second, jobs: map[string]*window{},
	}
}

// Wants reports whether a decision should alert, per the OnDeny setting.
func (d *Dispatcher) Wants(decision string, ruleAlert bool) bool {
	return ruleAlert || (decision == "deny" && d.opts.OnDeny == DenyAll)
}

// Send queues an alert if Wants says so. It never blocks: if the queue is
// full the alert is dropped and counted.
func (d *Dispatcher) Send(a Alert) {
	if d == nil || len(d.notifiers) == 0 || !d.Wants(a.Decision, a.RuleAlert) {
		return
	}
	if a.Time.IsZero() {
		a.Time = d.now()
	}
	if d.opts.LinkBase != "" && a.AuditSeq > 0 {
		a.Link = fmt.Sprintf("%s/audit/%d", strings.TrimRight(d.opts.LinkBase, "/"), a.AuditSeq)
	}
	select {
	case d.queue <- a:
	default:
		d.dropped.Add(1)
		d.log.Warn("alert queue full; alert dropped", "job", a.JobID, "action", a.Action)
	}
}

// Stats returns counters for alerts sent, failed (after every attempt) and
// dropped (queue full).
func (d *Dispatcher) Stats() (sent, failed, dropped int64) {
	return d.sent.Load(), d.failed.Load(), d.dropped.Load()
}

// Run delivers queued alerts until ctx ends, then drains what's queued for
// up to a few seconds.
func (d *Dispatcher) Run(ctx context.Context) {
	tick := time.NewTicker(d.opts.Window / 2)
	defer tick.Stop()
	for {
		select {
		case a := <-d.queue:
			if ctx.Err() != nil { // select picks at random once ctx is done too
				d.drain(ctx, &a)
				return
			}
			d.handle(ctx, a)
		case <-tick.C:
			d.flushSummaries(ctx, false)
		case <-ctx.Done():
			d.drain(ctx, nil)
			return
		}
	}
}

// drain delivers what's queued, and every pending summary, with a few
// seconds' grace after shutdown begins.
func (d *Dispatcher) drain(ctx context.Context, first *Alert) {
	grace, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if first != nil {
		d.handle(grace, *first)
	}
	for {
		select {
		case a := <-d.queue:
			d.handle(grace, a)
		default:
			d.flushSummaries(grace, true)
			return
		}
	}
}

// handle coalesces per job: the first PerJob alerts in a window go out; the
// rest are counted and reported in one summary when the window ends.
func (d *Dispatcher) handle(ctx context.Context, a Alert) {
	d.mu.Lock()
	w, ok := d.jobs[a.JobID]
	now := d.now()
	if !ok || now.Sub(w.start) >= d.opts.Window {
		var carried int
		if ok {
			carried = w.suppressed
		}
		w = &window{start: now}
		d.jobs[a.JobID] = w
		a.Suppressed += carried
	}
	w.n++
	if w.n > d.opts.PerJob {
		w.suppressed++
		w.last = a
		d.mu.Unlock()
		return
	}
	d.mu.Unlock()
	d.deliver(ctx, a)
}

// flushSummaries sends one summary per job whose window ended with alerts
// held back, so a burst is never silently lost.
func (d *Dispatcher) flushSummaries(ctx context.Context, all bool) {
	now := d.now()
	var out []Alert
	d.mu.Lock()
	for id, w := range d.jobs {
		if now.Sub(w.start) < d.opts.Window && !all {
			continue
		}
		if w.suppressed > 0 {
			s := w.last
			s.Suppressed = w.suppressed - 1 // w.last itself is the one sent
			out = append(out, s)
		}
		delete(d.jobs, id)
	}
	d.mu.Unlock()
	for _, a := range out {
		d.deliver(ctx, a)
	}
}

func (d *Dispatcher) deliver(ctx context.Context, a Alert) {
	for _, n := range d.notifiers {
		var err error
		for attempt := 1; attempt <= d.opts.Attempts; attempt++ {
			actx, cancel := context.WithTimeout(ctx, d.opts.Timeout)
			err = n.Notify(actx, a)
			cancel()
			if err == nil {
				break
			}
			if attempt < d.opts.Attempts {
				select {
				case <-time.After(d.backoff * time.Duration(attempt)):
				case <-ctx.Done():
				}
			}
		}
		if err != nil {
			d.failed.Add(1)
			d.log.Warn("alert not delivered", "notifier", n.Name(), "job", a.JobID, "action", a.Action, "err", err)
			continue
		}
		d.sent.Add(1)
	}
}
