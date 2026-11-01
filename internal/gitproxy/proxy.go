// Package gitproxy is Ariadne, the git smart-HTTP proxy (RFC decision 8).
// Agents clone, fetch and push through
// /git/{provider}/{owner}/{repo}.git with only their session token; each
// request becomes git.fetch or git.push in the pipeline, and an allowed one
// is reverse-proxied upstream with the job's minted credential in place of
// the session token. Only the smart-HTTP endpoints exist; no TLS is
// intercepted.
package gitproxy

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/jobs"
	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/pipeline"
)

// Prefix is where the proxy is mounted on the agent port.
const Prefix = "/git/"

// drainLimit bounds how much of a denied push's pack is read and thrown
// away so git sees the refusal instead of a broken pipe.
const drainLimit = 64 << 20

// Authorizer is the pipeline's authorize step.
type Authorizer interface {
	Authorize(ctx context.Context, p jobs.Principal, iface, action string, raw json.RawMessage) (*pipeline.Allowed, error)
}

// Proxy serves the git endpoints. It must sit behind jobs.RequireSession.
type Proxy struct {
	reg       *connector.Registry
	pl        Authorizer
	log       *slog.Logger
	transport http.RoundTripper
}

// New returns Ariadne.
func New(reg *connector.Registry, pl Authorizer, log *slog.Logger) *Proxy {
	return &Proxy{reg: reg, pl: pl, log: logging.For(log, logging.Ariadne), transport: &http.Transport{
		Proxy:                 nil, // upstreams are reached directly, never via the egress proxy
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   30 * time.Second,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
		// No response-header timeout: the upstream may take minutes to
		// index a large push before it answers. The client going away
		// cancels the request.
	}}
}

// target is a parsed proxy URL.
type target struct {
	provider string
	repo     string // canonical
	endpoint string // info/refs, git-upload-pack or git-receive-pack
	remote   connector.Connector
	git      connector.GitRemote
}

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pr, ok := jobs.PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	t, action, ok := p.route(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if action == "push" {
		p.push(w, r, pr, t)
		return
	}
	p.fetch(w, r, pr, t, r.Body)
}

// fetch authorizes git.fetch and forwards the request.
func (p *Proxy) fetch(w http.ResponseWriter, r *http.Request, pr jobs.Principal, t target, body io.Reader) {
	params, _ := json.Marshal(map[string]any{"provider": t.provider, "repo": t.repo})
	allowed, err := p.pl.Authorize(r.Context(), pr, audit.InterfaceGit, Namespace+".fetch", params)
	if err != nil {
		refuse(w, err)
		return
	}
	if body != r.Body {
		r.Header.Del("Content-Encoding") // body is the decompressed stream
	}
	p.forward(w, r, t, allowed, body)
}

// route maps the request to a provider, repo and action. Anything but the
// three smart-HTTP endpoints is not found.
func (p *Proxy) route(r *http.Request) (target, string, bool) {
	if r.URL.RawPath != "" { // escaped characters: no repo name needs them
		return target{}, "", false
	}
	rest, ok := strings.CutPrefix(r.URL.Path, Prefix)
	if !ok {
		return target{}, "", false
	}
	var t target
	var action string
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(rest, "/info/refs"):
		t.endpoint = "info/refs"
		switch q := r.URL.Query(); {
		case len(q) != 1 || len(q["service"]) != 1:
			return target{}, "", false // dumb HTTP, or something else
		case q.Get("service") == "git-upload-pack", q.Get("service") == "git-receive-pack":
			action = "fetch" // the advertisement before a push reveals only refs
		default:
			return target{}, "", false
		}
	case r.Method == http.MethodPost && strings.HasSuffix(rest, "/git-upload-pack"):
		t.endpoint, action = "git-upload-pack", "fetch"
	case r.Method == http.MethodPost && strings.HasSuffix(rest, "/git-receive-pack"):
		t.endpoint, action = "git-receive-pack", "push"
	default:
		return target{}, "", false
	}
	rest = strings.TrimSuffix(strings.TrimSuffix(rest, "/"+t.endpoint), ".git")
	parts := strings.Split(rest, "/")
	if len(parts) != 3 {
		return target{}, "", false
	}
	t.provider = parts[0]
	c, ok := p.reg.Connector(t.provider)
	if !ok {
		return target{}, "", false
	}
	if t.git, ok = c.(connector.GitRemote); !ok {
		return target{}, "", false
	}
	repo, err := t.git.GitRepo(parts[1] + "/" + parts[2])
	if err != nil {
		return target{}, "", false
	}
	t.repo, t.remote = repo, c
	return t, action, true
}

// push reads the ref updates, asks policy about all of them, and on an
// allow sends what it read plus the rest of the body upstream untouched.
func (p *Proxy) push(w http.ResponseWriter, r *http.Request, pr jobs.Principal, t target) {
	body := io.Reader(r.Body)
	switch enc := r.Header.Get("Content-Encoding"); enc {
	case "", "identity":
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			p.malformed(w, r, pr, t, fmt.Errorf("%w: bad gzip body", ErrMalformed))
			return
		}
		defer func() { _ = zr.Close() }()
		body = zr
	default:
		p.malformed(w, r, pr, t, fmt.Errorf("%w: unsupported content encoding", ErrMalformed))
		return
	}
	br := bufio.NewReaderSize(body, 64<<10)
	if b, err := br.Peek(5); string(b) == "0000" && errors.Is(err, io.EOF) {
		// A body of only a flush is git's probe before a large chunked
		// push: it updates nothing and checks access, like the ref
		// advertisement, so it is a fetch.
		p.fetch(w, r, pr, t, io.MultiReader(strings.NewReader("0000"), br))
		return
	}
	cmds, err := ParseCommands(br)
	if err != nil {
		p.malformed(w, r, pr, t, err)
		return
	}
	params, _ := json.Marshal(map[string]any{"provider": t.provider, "repo": t.repo, "refs": cmds.Refs})
	allowed, err := p.pl.Authorize(r.Context(), pr, audit.InterfaceGit, Namespace+".push", params)
	if err != nil {
		var denied *pipeline.Denied
		if !errors.As(err, &denied) {
			refuse(w, err)
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(br, drainLimit))
		reportDenied(w, cmds, denied.Error())
		return
	}
	// The body upstream is the decompressed stream: what was parsed,
	// then everything after it, unread and unchanged.
	r.Header.Del("Content-Encoding")
	p.forward(w, r, t, allowed, io.MultiReader(strings.NewReader(string(cmds.Raw)), br))
}

// malformed denies a push Valet can't read, through the pipeline so it is
// audited like any other refusal.
func (p *Proxy) malformed(w http.ResponseWriter, r *http.Request, pr jobs.Principal, t target, why error) {
	params, _ := json.Marshal(map[string]any{"provider": t.provider, "repo": t.repo, "refs": []any{}, "malformed": why.Error()})
	_, err := p.pl.Authorize(r.Context(), pr, audit.InterfaceGit, Namespace+".push", params)
	if err == nil { // can't happen: the params fail the schema
		err = errors.New("refused")
	}
	var denied *pipeline.Denied
	if errors.As(err, &denied) {
		err = &pipeline.Denied{Reason: why.Error()}
	}
	refuse(w, err)
}

// forward proxies the request upstream with the job's credential.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, t target, allowed *pipeline.Allowed, body io.Reader) {
	cred, err := allowed.Credential(r.Context(), t.remote)
	if err != nil {
		p.log.Warn("no upstream credential", "provider", t.provider, "repo", t.repo, "err", err)
		http.Error(w, "valet: no upstream credential for this job", http.StatusBadGateway)
		return
	}
	base, err := t.git.GitURL(t.repo)
	if err != nil {
		allowed.Done(0, err)
		http.Error(w, "valet: no upstream for this repository", http.StatusBadGateway)
		return
	}
	status, upstreamErr := 0, error(nil)
	rp := &httputil.ReverseProxy{
		Rewrite: func(out *httputil.ProxyRequest) {
			u := *base
			u.Path = strings.TrimSuffix(u.Path, "/") + "/" + t.endpoint
			u.RawPath, u.RawQuery = "", out.In.URL.RawQuery
			out.Out.URL, out.Out.Host = &u, u.Host
			out.Out.Body = io.NopCloser(body)
			out.Out.ContentLength = -1
			if body == r.Body {
				out.Out.ContentLength = r.ContentLength
			}
			// Only what git needs goes upstream: never the session token.
			h := http.Header{}
			for _, k := range []string{"Content-Type", "Content-Encoding", "Accept", "Accept-Encoding", "Git-Protocol", "User-Agent"} {
				if v := out.In.Header.Values(k); len(v) > 0 {
					h[k] = v
				}
			}
			out.Out.Header = h
			t.git.GitAuth(out.Out, cred)
		},
		Transport:     p.transport,
		FlushInterval: -1, // stream sideband progress as it comes
		ModifyResponse: func(resp *http.Response) error {
			status = resp.StatusCode
			for _, k := range []string{"Set-Cookie", "WWW-Authenticate", "Authorization"} {
				resp.Header.Del(k)
			}
			if resp.StatusCode == http.StatusUnauthorized {
				// Upstream refused Valet's credential. A 401 would make git
				// ask the agent for a password; it has none to give.
				return errors.New("upstream refused the job's credential")
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			upstreamErr = err
			p.log.Warn("upstream request failed", "provider", t.provider, "repo", t.repo, "endpoint", t.endpoint, "err", err)
			http.Error(w, "valet: the upstream request failed", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
	allowed.Done(status, upstreamErr)
}

// refuse answers a denied or failed request. git shows a text/plain body
// from the ref discovery request to the user.
func refuse(w http.ResponseWriter, err error) {
	var denied *pipeline.Denied
	if errors.As(err, &denied) {
		http.Error(w, "valet: "+denied.Error(), http.StatusForbidden)
		return
	}
	http.Error(w, "valet: the request could not be recorded, so it was not done", http.StatusInternalServerError)
}

// reportDenied answers a refused push the way a server refusing it would:
// a report-status with "ng" for every ref, so git prints the reason next to
// each one, plus the reason on the progress channel ("remote: …").
func reportDenied(w http.ResponseWriter, cmds *Commands, reason string) {
	reason = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, reason)
	if len(reason) > 200 {
		reason = reason[:200]
	}
	var report strings.Builder
	report.WriteString(pkt("unpack ok\n"))
	for _, ref := range cmds.Refs {
		report.WriteString(pkt("ng " + ref.Name + " " + reason + "\n"))
	}
	report.WriteString("0000")

	w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
	w.Header().Set("Cache-Control", "no-cache")
	var out strings.Builder
	switch {
	case cmds.HasCap("side-band-64k"), cmds.HasCap("side-band"):
		out.WriteString(pkt("\x02valet: " + reason + "\n"))
		// Band 1 carries the report, split to fit the packet limit:
		// 65520 bytes with side-band-64k, 1000 with plain side-band.
		chunk := maxPayload - 1
		if !cmds.HasCap("side-band-64k") {
			chunk = 1000 - 5
		}
		for rest := report.String(); rest != ""; {
			n := min(len(rest), chunk)
			out.WriteString(pkt("\x01" + rest[:n]))
			rest = rest[n:]
		}
		out.WriteString("0000")
	case cmds.HasCap("report-status"), cmds.HasCap("report-status-v2"):
		out.WriteString(report.String())
	default:
		// Nothing to report into: an HTTP error is all git can show.
		http.Error(w, "valet: "+reason, http.StatusForbidden)
		return
	}
	_, _ = io.WriteString(w, out.String())
}
