// Package throttle limits how often one source's failed authentications are
// recorded.
//
// The agent is the adversary (RFC Threat model): left unchecked, it could
// send bad tokens in a loop and make every failure a synchronous audit write,
// filling the disk and queueing legitimate audit writes behind its own. A
// Throttle lets the first failures in a window through to be audited one by
// one, reports the moment a source crosses the limit so that can be audited
// once, and turns everything after into a cheap refusal with no write.
package throttle

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// Verdict says what to do with one failure.
type Verdict int

// Verdicts.
const (
	Record      Verdict = iota // audit this failure as usual
	RecordLimit                // audit that the source hit the limit; refuse
	Suppress                   // refuse without auditing
)

// Defaults: ten audited failures per source per minute.
const (
	DefaultLimit  = 10
	DefaultWindow = time.Minute
	maxSources    = 10000
)

type bucket struct {
	start time.Time
	n     int
}

// Throttle counts failures per source in fixed windows.
type Throttle struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	sources map[string]*bucket
	now     func() time.Time
}

// New returns a Throttle allowing limit recorded failures per window.
func New(limit int, window time.Duration) *Throttle {
	return &Throttle{limit: limit, window: window, sources: map[string]*bucket{}, now: time.Now}
}

// Failure counts a failure from source and says how to handle it.
func (t *Throttle) Failure(source string) Verdict {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	b, ok := t.sources[source]
	if !ok || now.Sub(b.start) >= t.window {
		if !ok && len(t.sources) >= maxSources {
			t.prune(now)
			if len(t.sources) >= maxSources {
				// Too many live sources: treat this one as over the limit
				// rather than grow without bound.
				return Suppress
			}
		}
		b = &bucket{start: now}
		t.sources[source] = b
	}
	b.n++
	switch {
	case b.n <= t.limit:
		return Record
	case b.n == t.limit+1:
		return RecordLimit
	default:
		return Suppress
	}
}

func (t *Throttle) prune(now time.Time) {
	for k, b := range t.sources {
		if now.Sub(b.start) >= t.window {
			delete(t.sources, k)
		}
	}
}

// Source is the key for r: its remote IP, without the port, so reconnecting
// doesn't reset the count.
func Source(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RetryAfter is the Retry-After value, in seconds, for a refused request.
func (t *Throttle) RetryAfter() int { return int(t.window / time.Second) }
