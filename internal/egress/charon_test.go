package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xcwds/valet/internal/alert"
	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/jobs"
	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/store"
)

var ctx = context.Background()

// publicIP is what the fake resolver answers for allowed test names; the
// fake dialer sends it to the local upstream.
var publicIP = netip.MustParseAddr("93.184.215.14")

type alerts struct {
	mu  sync.Mutex
	got []alert.Alert
}

func (a *alerts) Send(x alert.Alert) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.got = append(a.got, x)
}

type env struct {
	t        *testing.T
	db       *store.Store
	jobs     *jobs.Service
	charon   *Charon
	proxy    *httptest.Server
	upstream *httptest.Server // TLS, stands in for a registry
	echo     net.Listener     // raw TCP echo upstream
	alerts   *alerts
	mu       sync.Mutex
	dialed   []string
	dns      map[string][]netip.Addr
	// onResolve runs between authentication and the tunnel opening.
	onResolve func(host string)
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, alerts: &alerts{}}
	var err error
	e.db, err = store.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.db.Close() })
	log := logging.New(io.Discard, "json", slog.LevelInfo)
	alog := audit.New(e.db, log)
	e.jobs = jobs.NewService(e.db, alog)

	e.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "package index for %s", r.URL.Path)
	}))
	t.Cleanup(e.upstream.Close)
	e.echo, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.echo.Close() })
	go func() {
		for {
			c, err := e.echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()

	e.dns = map[string][]netip.Addr{
		"registry.npmjs.org":      {publicIP},
		"files.pythonhosted.org":  {publicIP, netip.MustParseAddr("2606:4700::6810:1")},
		"echo.example.com":        {netip.MustParseAddr("93.184.215.15")},
		"evil.example.org":        {publicIP},
		"lan.pythonhosted.org":    {netip.MustParseAddr("10.0.0.5")},
		"loop.pythonhosted.org":   {netip.MustParseAddr("127.0.0.1")},
		"meta.pythonhosted.org":   {netip.MustParseAddr("169.254.169.254")},
		"mixed.pythonhosted.org":  {publicIP, netip.MustParseAddr("192.168.1.10")},
		"v6lan.pythonhosted.org":  {netip.MustParseAddr("fd00::1")},
		"mapped.pythonhosted.org": {netip.MustParseAddr("::ffff:10.1.2.3")},
	}
	e.charon = New(Options{
		Allow: []string{"registry.npmjs.org", "*.pythonhosted.org", "echo.example.com"},
		Ports: []int{443},
		Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			if e.onResolve != nil {
				e.onResolve(host)
			}
			if a, ok := e.dns[host]; ok {
				return a, nil
			}
			return nil, fmt.Errorf("no such host %s", host)
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			e.mu.Lock()
			e.dialed = append(e.dialed, addr)
			e.mu.Unlock()
			target := e.upstream.Listener.Addr().String()
			if strings.HasPrefix(addr, "93.184.215.15:") {
				target = e.echo.Addr().String()
			} else if !strings.HasPrefix(addr, publicIP.String()+":") && !strings.HasPrefix(addr, "[2606:4700::6810:1]:") {
				return nil, fmt.Errorf("test dialer: unexpected %s", addr)
			}
			return (&net.Dialer{}).DialContext(ctx, network, target)
		},
	}, e.jobs, alog, log)
	e.charon.SetAlerter(e.alerts)
	e.jobs.OnRevoke(func(_ context.Context, id string) { e.charon.CloseJob(id) })
	e.proxy = httptest.NewServer(e.charon)
	t.Cleanup(e.proxy.Close)
	return e
}

func (e *env) job() (jobs.Job, string) {
	e.t.Helper()
	j, tok, err := e.jobs.Create(ctx, jobs.CreateRequest{Role: "implementer", Repos: []string{"xcwds/site"}, CreatedBy: "admin:test", TTL: time.Hour})
	if err != nil {
		e.t.Fatal(err)
	}
	return j, tok
}

func (e *env) trail(jobID string) []audit.Record {
	e.t.Helper()
	recs, err := audit.Tail(ctx, e.db.Read(), audit.Filter{JobID: jobID, Limit: 1000})
	if err != nil {
		e.t.Fatal(err)
	}
	var out []audit.Record
	for _, r := range recs {
		if r.Interface == audit.InterfaceEgress {
			out = append(out, r)
		}
	}
	return out
}

// connect sends a raw CONNECT and returns the status and the open
// connection (for a 200, the tunnel).
func (e *env) connect(target, proxyAuth string) (int, net.Conn, *bufio.Reader) {
	e.t.Helper()
	c, err := net.Dial("tcp", e.proxy.Listener.Addr().String())
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = c.Close() })
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if proxyAuth != "" {
		req += "Proxy-Authorization: " + proxyAuth + "\r\n"
	}
	if _, err := io.WriteString(c, req+"\r\n"); err != nil {
		e.t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		e.t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	return resp.StatusCode, c, br
}

func basic(tok string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("agent:"+tok))
}

// A package manager configured with HTTPS_PROXY=http://agent:TOKEN@valet
// fetches from an allowed registry through the tunnel.
func TestAllowedHostThroughARealClient(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job()
	proxyURL, _ := url.Parse(e.proxy.URL)
	proxyURL.User = url.UserPassword("agent", tok)
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		// The test upstream's certificate isn't for registry.npmjs.org;
		// what's under test is the tunnel, not the TLS inside it.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test upstream
	}}
	resp, err := client.Get("https://registry.npmjs.org/left-pad")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	client.CloseIdleConnections()
	if string(body) != "package index for /left-pad" {
		t.Fatalf("body = %q", body)
	}

	var recs []audit.Record
	deadline := time.Now().Add(5 * time.Second)
	for len(recs) < 2 && time.Now().Before(deadline) {
		recs = e.trail(j.ID)
		time.Sleep(10 * time.Millisecond)
	}
	if len(recs) != 2 {
		t.Fatalf("audit = %+v", recs)
	}
	d, r := recs[0], recs[1]
	if d.Action != ActionConnect || d.Decision != audit.Allow || d.Rule != "egress:registry.npmjs.org" ||
		string(d.Params) != `{"host":"registry.npmjs.org","port":443}` {
		t.Errorf("decision = %+v", d)
	}
	if r.Decision != audit.Info || !strings.Contains(string(r.Params), `"bytes_up":`) || strings.Contains(string(r.Params), `"bytes_down":0`) {
		t.Errorf("result = %+v %s", r, r.Params)
	}
}

func TestDenials(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job()
	for _, c := range []struct {
		target, rule string
		status       int
	}{
		{"evil.example.org:443", "egress/allowlist", 403},
		{"pythonhosted.org:443", "egress/allowlist", 403}, // *.suffix is subdomains only
		{"registry.npmjs.org.evil.org:443", "egress/allowlist", 403},
		{"93.184.215.14:443", "egress/allowlist", 403}, // an IP is never on the list
		{"registry.npmjs.org:22", "egress/port", 403},
		{"registry.npmjs.org:80", "egress/port", 403},
		{"lan.pythonhosted.org:443", "egress/private-address", 403},
		{"loop.pythonhosted.org:443", "egress/private-address", 403},
		{"meta.pythonhosted.org:443", "egress/private-address", 403},
		{"mixed.pythonhosted.org:443", "egress/private-address", 403},
		{"v6lan.pythonhosted.org:443", "egress/private-address", 403},
		{"mapped.pythonhosted.org:443", "egress/private-address", 403},
		{"nx.pythonhosted.org:443", "egress/dns", 502},
	} {
		t.Run(c.target, func(t *testing.T) {
			status, _, _ := e.connect(c.target, basic(tok))
			if status != c.status {
				t.Errorf("status %d, want %d", status, c.status)
			}
			recs := e.trail(j.ID)
			last := recs[len(recs)-1]
			if last.Action != ActionConnect || last.Decision != audit.Deny || last.Rule != c.rule {
				t.Errorf("audit = %+v", last)
			}
		})
	}
	if len(e.dialed) != 0 {
		t.Errorf("denied targets were dialed: %v", e.dialed)
	}
	e.alerts.mu.Lock()
	defer e.alerts.mu.Unlock()
	if len(e.alerts.got) != 13 || e.alerts.got[0].Rule != "egress/allowlist" || e.alerts.got[0].JobID != j.ID {
		t.Errorf("%d alerts: %+v", len(e.alerts.got), e.alerts.got)
	}
}

func TestPrivateAddressParamsNameTheAddress(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job()
	e.connect("meta.pythonhosted.org:443", basic(tok))
	recs := e.trail(j.ID)
	if p := string(recs[len(recs)-1].Params); !strings.Contains(p, `"address":"169.254.169.254"`) {
		t.Errorf("params = %s", p)
	}
}

func TestPlainHTTPIsOff(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job()
	proxyURL, _ := url.Parse(e.proxy.URL)
	proxyURL.User = url.UserPassword("agent", tok)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get("http://registry.npmjs.org/left-pad")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("plain HTTP: %d", resp.StatusCode)
	}
	recs := e.trail(j.ID)
	if last := recs[len(recs)-1]; last.Action != ActionHTTP || last.Decision != audit.Deny || last.Rule != "egress/https-only" {
		t.Errorf("audit = %+v", last)
	}
}

func TestAuthentication(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job()
	before, _ := audit.Tail(ctx, e.db.Read(), audit.Filter{Limit: 1000})

	// No credentials: a challenge, not audited.
	status, c, _ := e.connect("registry.npmjs.org:443", "")
	_ = c.Close()
	if status != http.StatusProxyAuthRequired {
		t.Errorf("no token: %d", status)
	}
	after, _ := audit.Tail(ctx, e.db.Read(), audit.Filter{Limit: 1000})
	if len(after) != len(before) {
		t.Error("an anonymous challenge was audited")
	}
	// Wrong, malformed, or revoked: refused and audited as failed logins.
	for name, auth := range map[string]string{
		"bogus":       basic("vlt_sess_" + strings.Repeat("a", 52)),
		"not base64":  "Basic !!!",
		"no password": "Basic " + base64.StdEncoding.EncodeToString([]byte("agent")),
		"other type":  "Digest x",
		"admin token": "Bearer vlt_admin_" + strings.Repeat("b", 52),
	} {
		if status, c, _ := e.connect("registry.npmjs.org:443", auth); status != http.StatusProxyAuthRequired {
			t.Errorf("%s: %d", name, status)
		} else {
			_ = c.Close()
		}
	}
	if err := e.jobs.Revoke(ctx, j.ID, "admin:test", "done"); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := e.connect("registry.npmjs.org:443", basic(tok)); status != http.StatusProxyAuthRequired {
		t.Errorf("revoked: %d", status)
	}
	all, _ := audit.Tail(ctx, e.db.Read(), audit.Filter{Limit: 1000})
	failed := 0
	for _, r := range all {
		if r.Action == "session.authenticate" && r.Decision == audit.Deny && r.Interface == audit.InterfaceEgress {
			failed++
		}
	}
	if failed != 6 {
		t.Errorf("%d audited failed logins, want 6", failed)
	}
	if len(e.dialed) != 0 {
		t.Error("an unauthenticated CONNECT was dialed")
	}
}

func TestBearerAndBufferedClientBytes(t *testing.T) {
	e := newEnv(t)
	_, tok := e.job()
	// Bytes sent right behind the CONNECT (before the 200) must not be lost.
	c, err := net.Dial("tcp", e.proxy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "CONNECT echo.example.com:443 HTTP/1.1\r\nHost: echo.example.com:443\r\nProxy-Authorization: Bearer "+tok+"\r\n\r\nearly-bytes")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close() // a 200 to CONNECT has no body; the tunnel follows
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	got := make([]byte, len("early-bytes"))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "early-bytes" {
		t.Fatalf("echo = %q %v", got, err)
	}
}

func TestRevokingTheJobClosesItsTunnels(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job()
	status, c, br := e.connect("echo.example.com:443", basic(tok))
	if status != 200 {
		t.Fatalf("connect: %d", status)
	}
	_, _ = io.WriteString(c, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo: %q %v", buf, err)
	}
	if err := e.jobs.Revoke(ctx, j.ID, "admin:test", "stop"); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("the tunnel stayed open after the job was revoked")
	} else if ne := net.Error(nil); errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("the tunnel stayed open after the job was revoked (read timed out)")
	}
}

func TestTunnelLimitPerJob(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job()
	for i := range MaxTunnelsPerJob {
		if status, _, _ := e.connect("echo.example.com:443", basic(tok)); status != 200 {
			t.Fatalf("tunnel %d: %d", i, status)
		}
	}
	if status, _, _ := e.connect("echo.example.com:443", basic(tok)); status != http.StatusTooManyRequests {
		t.Errorf("tunnel %d: %d, want 429", MaxTunnelsPerJob+1, status)
	}
	recs := e.trail(j.ID)
	if last := recs[len(recs)-1]; last.Rule != "egress/limit" || last.Decision != audit.Deny {
		t.Errorf("audit = %+v", last)
	}
	// Another job is unaffected.
	_, tok2 := e.job()
	if status, _, _ := e.connect("echo.example.com:443", basic(tok2)); status != 200 {
		t.Errorf("another job: %d", status)
	}
}

func TestPublic(t *testing.T) {
	for s, want := range map[string]bool{
		"93.184.215.14": true, "2606:4700::6810:1": true, "8.8.8.8": true,
		"10.1.2.3": false, "172.16.0.1": false, "192.168.0.1": false, "127.0.0.1": false, "0.0.0.0": false,
		"169.254.169.254": false, "100.64.0.1": false, "198.18.0.1": false, "255.255.255.255": false, "224.0.0.1": false,
		"::1": false, "::": false, "fe80::1": false, "fd00::1": false, "fc00::1": false, "ff02::1": false,
		"::ffff:10.0.0.1": false, "::ffff:8.8.8.8": true, "64:ff9b::a00:1": false, "2002:a00:1::": false,
		"2001:db8::1": false, "2001:0:a00:1::": false, "fec0::1": false,
	} {
		if got := public(netip.MustParseAddr(s)); got != want {
			t.Errorf("public(%s) = %v, want %v", s, got, want)
		}
	}
}

func TestAllowlistAndTargets(t *testing.T) {
	a := newAllowlist([]string{"registry.npmjs.org", "*.pythonhosted.org"})
	for host, want := range map[string]string{
		"registry.npmjs.org": "registry.npmjs.org", "files.pythonhosted.org": "*.pythonhosted.org",
		"a.b.pythonhosted.org": "*.pythonhosted.org", "pythonhosted.org": "", "evilpythonhosted.org": "",
		"registry.npmjs.org.evil": "", "npmjs.org": "", "": "",
	} {
		if got := a.match(host); got != want {
			t.Errorf("match(%q) = %q, want %q", host, got, want)
		}
	}
	for target, want := range map[string]string{"Registry.NPMjs.org.:443": "registry.npmjs.org", "x.org:443": "x.org"} {
		if h, _, err := splitTarget(target); err != nil || h != want {
			t.Errorf("splitTarget(%q) = %q %v", target, h, err)
		}
	}
	for _, bad := range []string{"x.org", ":443", "x.org:0", "x.org:70000", "x.org:https"} {
		if _, _, err := splitTarget(bad); err == nil {
			t.Errorf("splitTarget(%q) accepted", bad)
		}
	}
}

// A revoke landing after authentication but before the tunnel opens still
// stops it.
func TestRevokeDuringConnect(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job()
	e.onResolve = func(string) {
		if err := e.jobs.Revoke(ctx, j.ID, "admin:test", "mid-connect"); err != nil {
			t.Error(err)
		}
	}
	if status, _, _ := e.connect("echo.example.com:443", basic(tok)); status != http.StatusProxyAuthRequired {
		t.Errorf("status %d, want 407", status)
	}
	if len(e.dialed) != 0 {
		t.Errorf("dialed for a revoked job: %v", e.dialed)
	}
}

// Shutting down closes open tunnels and records each one's result.
func TestCloseRecordsOpenTunnels(t *testing.T) {
	e := newEnv(t)
	j, tok := e.job()
	status, c, br := e.connect("echo.example.com:443", basic(tok))
	if status != 200 {
		t.Fatalf("connect: %d", status)
	}
	_, _ = io.WriteString(c, "ping")
	if _, err := io.ReadFull(br, make([]byte, 4)); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	e.charon.Close(cctx)
	recs := e.trail(j.ID)
	last := recs[len(recs)-1]
	if last.Decision != audit.Info || !strings.Contains(string(last.Params), `"bytes_up":4`) || !strings.Contains(string(last.Params), `"bytes_down":4`) {
		t.Errorf("result after Close = %+v %s", last, last.Params)
	}
	if status, _, _ := e.connect("echo.example.com:443", basic(tok)); status != http.StatusServiceUnavailable {
		t.Errorf("after Close: %d, want 503", status)
	}
}
