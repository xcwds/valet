package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/throttle"
)

type principalKey struct{}

// PrincipalFrom returns the session RequireSession authenticated.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// SessionToken extracts a session token from a request: a Bearer token (MCP)
// or the password of HTTP basic auth (git, whose credential helpers speak
// basic auth; the username is ignored).
func SessionToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if tok, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(tok)
		}
	}
	if _, pass, ok := r.BasicAuth(); ok {
		return pass
	}
	return ""
}

// interfaceFor names the agent interface a request came through, for audit.
func interfaceFor(r *http.Request) string {
	if strings.HasPrefix(r.URL.Path, "/git/") {
		return audit.InterfaceGit
	}
	return audit.InterfaceMCP
}

// RequireSession authenticates every request on the agent port before next
// sees it. A wrong token gets 401 and is audited (and throttled per source);
// no credentials at all is just a challenge. next finds the session with
// PrincipalFrom.
func (s *Service) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			// A challenge, not a failed login: git asks anonymously first
			// and only then runs its credential helper, every command.
			// Nothing was guessed, so nothing is audited or throttled
			// (and with no write, there's nothing to flood).
			challenge(w)
			return
		}
		p, err := s.Authenticate(r.Context(), SessionToken(r), interfaceFor(r), throttle.Source(r))
		if err != nil {
			if errors.Is(err, ErrThrottled) {
				w.Header().Set("Retry-After", strconv.Itoa(s.throttle.RetryAfter()))
				http.Error(w, "too many failed authentications", http.StatusTooManyRequests)
				return
			}
			if errors.Is(err, ErrUnauthenticated) {
				challenge(w)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}

func challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="valet", Basic realm="valet"`)
	http.Error(w, "unauthenticated", http.StatusUnauthorized)
}

// EnrollPath is where containers exchange their enrollment code, on the
// agent port, outside RequireSession (the caller has no session yet).
const EnrollPath = "/enroll"

// EnrollHandler serves POST /enroll {"code": "vlt_enroll_…"}. A refusal is
// one generic 403 (the audit log has the reason); 429 means throttled and
// 503 a transient failure worth retrying with the same code.
func (s *Service) EnrollHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Code string `json:"code"`
		}
		// An unreadable body is a malformed code: refused and audited.
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req)
		body, err := s.Enroll(r.Context(), req.Code, throttle.Source(r))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		switch {
		case err == nil:
			w.Header().Set("X-Content-Type-Options", "nosniff")
			_, _ = w.Write(body) //nolint:gosec // G705: JSON Valet marshaled, served as application/json
		case errors.Is(err, ErrThrottled):
			w.Header().Set("Retry-After", strconv.Itoa(s.throttle.RetryAfter()))
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"too many failed attempts"}`))
		case errors.Is(err, ErrEnrollRefused):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"enrollment refused"}`))
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"try again"}`))
		}
	})
}
