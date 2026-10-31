package jobs

import (
	"context"
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
// sees it. Failures get 401 and are audited; next finds the session with
// PrincipalFrom.
func (s *Service) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := s.Authenticate(r.Context(), SessionToken(r), interfaceFor(r), throttle.Source(r))
		if err != nil {
			if errors.Is(err, ErrThrottled) {
				w.Header().Set("Retry-After", strconv.Itoa(s.throttle.RetryAfter()))
				http.Error(w, "too many failed authentications", http.StatusTooManyRequests)
				return
			}
			if errors.Is(err, ErrUnauthenticated) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="valet", Basic realm="valet"`)
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}
