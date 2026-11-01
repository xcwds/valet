// Package egress is Charon, the agents' egress proxy (RFC Deployment,
// decision 8). With no route out of agentnet, package managers reach their
// registries through it: HTTPS CONNECT tunnels to allowlisted hosts on
// allowed ports, attributed to a job by its session token, with no TLS
// interception and no credentials injected. It decides by host name only,
// the one exception to action-level policy (decision 6), and audits every
// tunnel, opened or refused.
package egress

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xcwds/valet/internal/alert"
	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/jobs"
	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/throttle"
)

// Action names in the audit log.
const (
	ActionConnect = "egress.connect"
	ActionHTTP    = "egress.http" // plain-HTTP forwarding, which is off
)

// MaxTunnelsPerJob bounds a job's open tunnels, so one agent can't
// exhaust Valet's file descriptors.
const MaxTunnelsPerJob = 64

// dialTimeout bounds connecting to an upstream.
const dialTimeout = 10 * time.Second

// Authenticator checks a session token (jobs.Service).
type Authenticator interface {
	Authenticate(ctx context.Context, token, iface, source string) (jobs.Principal, error)
}

// Alerter receives denials (alert.Dispatcher).
type Alerter interface{ Send(alert.Alert) }

// Options configure Charon.
type Options struct {
	Allow []string // host names and *.suffix patterns (config egress.allow)
	Ports []int    // allowed ports (config egress.ports)
	// Resolve and Dial default to the system resolver and a TCP dialer;
	// tests replace them.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Charon is the egress proxy. It is an http.Handler for the egress port.
type Charon struct {
	allow   allowlist
	ports   []int
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	auth    Authenticator
	audit   *audit.Log
	log     *slog.Logger
	alerts  Alerter

	mu      sync.Mutex
	tunnels map[string]map[*tunnel]struct{} // by job
}

// New returns Charon.
func New(opts Options, auth Authenticator, alog *audit.Log, log *slog.Logger) *Charon {
	c := &Charon{
		allow: newAllowlist(opts.Allow), ports: opts.Ports, resolve: opts.Resolve, dial: opts.Dial,
		auth: auth, audit: alog, log: logging.For(log, logging.Charon), tunnels: map[string]map[*tunnel]struct{}{},
	}
	if c.resolve == nil {
		c.resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	if c.dial == nil {
		c.dial = (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext
	}
	return c
}

// SetAlerter sends denials to a. Set it before serving.
func (c *Charon) SetAlerter(a Alerter) { c.alerts = a }

// ServeHTTP implements http.Handler.
func (c *Charon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := proxyToken(r)
	if token == "" {
		// A challenge, not a failed login: clients that only send
		// credentials when asked do so after this. Nothing is audited.
		challenge(w)
		return
	}
	p, err := c.auth.Authenticate(r.Context(), token, audit.InterfaceEgress, throttle.Source(r))
	switch {
	case errors.Is(err, jobs.ErrThrottled):
		http.Error(w, "too many failed authentications", http.StatusTooManyRequests)
		return
	case errors.Is(err, jobs.ErrUnauthenticated):
		challenge(w)
		return
	case err != nil:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if r.Method != http.MethodConnect {
		c.deny(w, r, p, audit.Event{Action: ActionHTTP, Params: map[string]any{"host": truncate(r.URL.Host, 255), "method": r.Method}},
			"egress/https-only", "plain-HTTP forwarding is off; only HTTPS (CONNECT) tunnels are allowed", http.StatusMethodNotAllowed)
		return
	}
	host, port, err := splitTarget(r.Host)
	ev := audit.Event{Action: ActionConnect, Params: map[string]any{"host": truncate(host, 255), "port": port}}
	if err != nil {
		ev.Params = map[string]any{"target": truncate(r.Host, 255)}
		c.deny(w, r, p, ev, "egress/target", "not a host:port", http.StatusBadRequest)
		return
	}
	if !slices.Contains(c.ports, port) {
		c.deny(w, r, p, ev, "egress/port", fmt.Sprintf("port %d is not allowed", port), http.StatusForbidden)
		return
	}
	rule := c.allow.match(host)
	if rule == "" {
		c.deny(w, r, p, ev, "egress/allowlist", host+" is not on the egress allowlist", http.StatusForbidden)
		return
	}
	// Resolve here and dial the vetted address: no second lookup can
	// swap in another one.
	addrs, err := c.resolve(r.Context(), host)
	if err != nil || len(addrs) == 0 {
		c.deny(w, r, p, ev, "egress/dns", "could not resolve "+host, http.StatusBadGateway)
		return
	}
	for _, a := range addrs {
		if !public(a) {
			ev.Params.(map[string]any)["address"] = a.Unmap().String()
			c.deny(w, r, p, ev, "egress/private-address", host+" resolves to a non-public address", http.StatusForbidden)
			return
		}
	}

	t, ok := c.register(p.Job.ID)
	if !ok {
		c.deny(w, r, p, ev, "egress/limit", fmt.Sprintf("more than %d open tunnels for this job", MaxTunnelsPerJob), http.StatusTooManyRequests)
		return
	}
	defer c.unregister(p.Job.ID, t)

	ev.JobID, ev.SessionID, ev.Interface = p.Job.ID, p.SessionID, audit.InterfaceEgress
	ev.Decision, ev.Rule = audit.Allow, "egress:"+rule
	decided, err := c.audit.Append(r.Context(), ev)
	if err != nil {
		http.Error(w, "valet: the request could not be recorded, so it was not done", http.StatusServiceUnavailable)
		return
	}
	result := audit.Event{JobID: p.Job.ID, SessionID: p.SessionID, Interface: audit.InterfaceEgress, Action: ActionConnect, Decision: audit.Info}
	resultParams := map[string]any{"result_of": decided.Seq}
	defer func() {
		result.Params = resultParams
		if _, err := c.audit.Append(context.WithoutCancel(r.Context()), result); err != nil {
			c.log.Error("a tunnel's result was not recorded", "job", p.Job.ID, "host", host, "err", err)
		}
	}()

	upstream, err := c.dialAny(r.Context(), addrs, port)
	if err != nil {
		result.Error = "connect failed"
		c.log.Warn("upstream connect failed", "host", host, "port", port, "err", err)
		http.Error(w, "valet: could not connect to "+host, http.StatusBadGateway)
		return
	}
	resultParams["address"] = upstream.RemoteAddr().String()

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		result.Error = "cannot hijack"
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		result.Error = "cannot hijack"
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		result.Error = "client gone"
		return
	}
	// A tunnel never outlives its job; revoking the job closes it sooner.
	_ = client.SetDeadline(p.Job.ExpiresAt)
	_ = upstream.SetDeadline(p.Job.ExpiresAt)
	t.attach(client, upstream)
	up, down := splice(client, buf.Reader, upstream)
	resultParams["bytes_up"], resultParams["bytes_down"] = up, down
}

// CloseJob closes every tunnel the job has open (on revoke).
func (c *Charon) CloseJob(jobID string) {
	c.mu.Lock()
	ts := c.tunnels[jobID]
	delete(c.tunnels, jobID)
	c.mu.Unlock()
	for t := range ts {
		t.close()
	}
}

// deny audits and alerts a refused request and answers it.
func (c *Charon) deny(w http.ResponseWriter, r *http.Request, p jobs.Principal, ev audit.Event, rule, reason string, status int) {
	ev.JobID, ev.SessionID, ev.Interface = p.Job.ID, p.SessionID, audit.InterfaceEgress
	ev.Decision, ev.Rule, ev.Error = audit.Deny, rule, reason
	rec, err := c.audit.Append(r.Context(), ev)
	if err != nil {
		c.log.Error("a refused tunnel was not recorded", "job", p.Job.ID, "err", err)
	} else if c.alerts != nil {
		c.alerts.Send(alert.Alert{
			JobID: rec.JobID, Role: p.Job.Role, Action: rec.Action, Decision: rec.Decision, Rule: rec.Rule,
			Reason: reason, Params: rec.Params, AuditSeq: rec.Seq,
		})
	}
	http.Error(w, "valet: denied by rule "+rule+": "+reason, status)
}

func (c *Charon) dialAny(ctx context.Context, addrs []netip.Addr, port int) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	var errs []error
	for _, a := range addrs {
		conn, err := c.dial(ctx, "tcp", net.JoinHostPort(a.Unmap().String(), strconv.Itoa(port)))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

// tunnel is one open CONNECT, closable from CloseJob.
type tunnel struct {
	mu     sync.Mutex
	conns  []net.Conn
	closed bool
}

func (t *tunnel) attach(cs ...net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.conns = cs
	if t.closed {
		for _, c := range cs {
			_ = c.Close()
		}
	}
}

func (t *tunnel) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	for _, c := range t.conns {
		_ = c.Close()
	}
}

func (c *Charon) register(jobID string) (*tunnel, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.tunnels[jobID]) >= MaxTunnelsPerJob {
		return nil, false
	}
	if c.tunnels[jobID] == nil {
		c.tunnels[jobID] = map[*tunnel]struct{}{}
	}
	t := &tunnel{}
	c.tunnels[jobID][t] = struct{}{}
	return t, true
}

func (c *Charon) unregister(jobID string, t *tunnel) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.tunnels[jobID], t)
	if len(c.tunnels[jobID]) == 0 {
		delete(c.tunnels, jobID)
	}
}

// splice copies both ways until both sides are done, half-closing so each
// direction can finish on its own, and returns the bytes each way.
// clientBuf holds anything the client sent right after its CONNECT.
func splice(client net.Conn, clientBuf *bufio.Reader, upstream net.Conn) (up, down int64) {
	var wg sync.WaitGroup
	var upN, downN atomic.Int64
	pipe := func(dst net.Conn, src io.Reader, n *atomic.Int64) {
		defer wg.Done()
		c, _ := io.Copy(dst, src)
		n.Store(c)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	wg.Add(2)
	go pipe(upstream, clientBuf, &upN)
	go pipe(client, upstream, &downN)
	wg.Wait()
	_ = client.Close()
	_ = upstream.Close()
	return upN.Load(), downN.Load()
}

// proxyToken reads the session token from Proxy-Authorization: Basic (the
// password; package managers take http://user:token@valet:14402) or Bearer.
func proxyToken(r *http.Request) string {
	h := r.Header.Get("Proxy-Authorization")
	if tok, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(tok)
	}
	if b64, ok := strings.CutPrefix(h, "Basic "); ok {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil {
			return "invalid"
		}
		_, pass, _ := strings.Cut(string(raw), ":")
		if pass == "" {
			return "invalid"
		}
		return pass
	}
	if h != "" {
		return "invalid" // credentials were offered: a failure, not a challenge
	}
	return ""
}

func challenge(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="valet"`)
	http.Error(w, "proxy authentication required: the session token as the password", http.StatusProxyAuthRequired)
}

// splitTarget parses a CONNECT target into a canonical host name and port.
func splitTarget(target string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("bad port %q", portStr)
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", 0, errors.New("empty host")
	}
	return host, port, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
