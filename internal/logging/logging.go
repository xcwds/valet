// Package logging builds valetd's structured logger.
//
// Every component logs with a "component" attribute holding its RFC name
// (themis, clio, ariadne, …). In JSON output that is an ordinary field; in text
// output it becomes a "[themis] " prefix on the message, as the RFC shows.
package logging

import (
	"context"
	"io"
	"log/slog"
)

// ComponentKey is the attribute that names the logging component.
const ComponentKey = "component"

// Component names from the RFC, used as log prefixes (RFC decision 15).
const (
	Valetd     = "valetd"
	Iris       = "iris"
	Ariadne    = "ariadne"
	Charon     = "charon"
	Themis     = "themis"
	Minos      = "minos"
	Hekate     = "hekate"
	Clio       = "clio"
	Hephaestus = "hephaestus"
)

// New returns a logger writing to w in format "json" or "text" at level.
func New(w io.Writer, format string, level slog.Leveler) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	if format == "text" {
		return slog.New(&prefixHandler{inner: slog.NewTextHandler(w, opts)})
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

// For returns a logger for the named component.
func For(l *slog.Logger, component string) *slog.Logger {
	return l.With(ComponentKey, component)
}

// prefixHandler turns the component attribute into a message prefix.
type prefixHandler struct {
	inner  slog.Handler
	prefix string
}

func (h *prefixHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *prefixHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.prefix != "" {
		r.Message = "[" + h.prefix + "] " + r.Message
	}
	return h.inner.Handle(ctx, r)
}

func (h *prefixHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	prefix := h.prefix
	rest := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		if a.Key == ComponentKey {
			prefix = a.Value.String()
			continue
		}
		rest = append(rest, a)
	}
	inner := h.inner
	if len(rest) > 0 {
		inner = inner.WithAttrs(rest)
	}
	return &prefixHandler{inner: inner, prefix: prefix}
}

func (h *prefixHandler) WithGroup(name string) slog.Handler {
	return &prefixHandler{inner: h.inner.WithGroup(name), prefix: h.prefix}
}
