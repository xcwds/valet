// Package daemon runs valetd's listeners.
//
// valetd serves three ports (RFC Architecture): admin (operator API and UI),
// agent (MCP and the git proxy) and egress (the registry proxy). Each is its
// own http.Server, so deployment can bind admin to a network agents can't
// reach. Until the components behind them land, the agent and egress ports
// refuse every request, which is the deny-by-default answer.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/xcwds/valet/internal/config"
	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/version"
)

// ShutdownTimeout bounds how long Run waits for in-flight requests on stop.
const ShutdownTimeout = 10 * time.Second

// Addrs are the addresses the listeners are bound to.
type Addrs struct {
	Admin, Agent, Egress string
}

// Options are Run's optional hooks.
type Options struct {
	// Ready is called with the bound addresses once every listener is up.
	Ready func(Addrs)
	// Health reports whether valetd's dependencies (the database) work;
	// /healthz answers 503 while it returns an error.
	Health func(context.Context) error
}

type listener struct {
	name string
	ln   net.Listener
	srv  *http.Server
}

// Run binds every listener, calls opts.Ready (if set) with their addresses,
// and serves until ctx is canceled or a listener fails. It then shuts all
// listeners down gracefully. It returns nil after a clean, requested stop.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger, opts Options) error {
	log = logging.For(log, logging.Valetd)

	specs := []struct {
		name, addr string
		srv        *http.Server
	}{
		{"admin", cfg.Listen.Admin, adminServer(opts.Health, log)},
		{"agent", cfg.Listen.Agent, agentServer()},
		{"egress", cfg.Listen.Egress, egressServer()},
	}

	// Requests get a base context that survives the stop signal, so the
	// shutdown grace period lets in-flight work finish. It is canceled when
	// that grace period runs out, or when Run returns.
	baseCtx, cancelBase := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelBase()

	var lns []listener
	closeAll := func() {
		for _, l := range lns {
			_ = l.ln.Close()
		}
	}
	var lc net.ListenConfig
	for _, s := range specs {
		ln, err := lc.Listen(ctx, "tcp", s.addr)
		if err != nil {
			closeAll()
			return fmt.Errorf("listen %s on %s: %w", s.name, s.addr, err)
		}
		s.srv.ErrorLog = slog.NewLogLogger(log.With("listener", s.name).Handler(), slog.LevelWarn)
		s.srv.BaseContext = func(net.Listener) context.Context { return baseCtx }
		lns = append(lns, listener{name: s.name, ln: ln, srv: s.srv})
	}

	addrs := Addrs{Admin: lns[0].ln.Addr().String(), Agent: lns[1].ln.Addr().String(), Egress: lns[2].ln.Addr().String()}
	log.Info("started", "version", version.String(), "admin", addrs.Admin, "agent", addrs.Agent, "egress", addrs.Egress)
	if opts.Ready != nil {
		opts.Ready(addrs)
	}

	errc := make(chan error, len(lns))
	for _, l := range lns {
		go func() {
			if err := l.srv.Serve(l.ln); !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s listener: %w", l.name, err)
				return
			}
			errc <- nil
		}()
	}

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("stopping")
	case runErr = <-errc:
		log.Error("listener failed, stopping", "err", runErr)
	}

	shutdownCtx, cancel := context.WithTimeout(baseCtx, ShutdownTimeout)
	defer cancel()
	stop := context.AfterFunc(shutdownCtx, cancelBase) // grace period over: cancel stragglers
	defer stop()
	for _, l := range lns {
		if err := l.srv.Shutdown(shutdownCtx); err != nil {
			log.Warn("shutdown did not finish cleanly", "listener", l.name, "err", err)
			_ = l.srv.Close()
		}
	}
	log.Info("stopped")
	return runErr
}

// testAdminHandler, when set by a test, replaces the admin routes.
var testAdminHandler http.Handler

// healthTimeout bounds the dependency check behind /healthz.
const healthTimeout = 2 * time.Second

// adminServer serves the operator API. For now: /healthz.
func adminServer(health func(context.Context) error, log *slog.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		status, code := "ok", http.StatusOK
		if health != nil {
			ctx, cancel := context.WithTimeout(r.Context(), healthTimeout)
			defer cancel()
			if err := health(ctx); err != nil {
				// The detail goes to the log, not to the client.
				log.Error("health check failed", "err", err)
				status, code = "unhealthy", http.StatusServiceUnavailable
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": status, "version": version.String()})
	})
	var h http.Handler = mux
	if testAdminHandler != nil {
		h = testAdminHandler
	}
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}

// agentServer will serve MCP (#14) and the git proxy (#17). Both stream
// (MCP responses, git packs), so there is no read or write timeout; the
// header timeout still bounds slow-loris clients.
func agentServer() *http.Server {
	return &http.Server{
		Handler:           refuse("no agent endpoints are enabled yet"),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}

// egressServer will be the registry CONNECT proxy (#18). Tunnels are long
// lived hijacked connections, so only the header and idle timeouts apply.
func egressServer() *http.Server {
	return &http.Server{
		Handler:           refuse("egress is not enabled yet"),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}

// refuse answers every request with 403: nothing is allowed until a component
// that decides is in place.
func refuse(msg string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, msg, http.StatusForbidden)
	})
}
