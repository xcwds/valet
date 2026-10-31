package secrets

import (
	"fmt"
	"log/slog"
)

// Redacted is what a Secret prints as, whatever the verb or encoder.
const Redacted = "[redacted]"

// Secret holds a secret value. Every way of printing or encoding it yields
// Redacted, so a stray %v, log attribute or JSON field can't leak it; the
// value is reachable only through Reveal.
type Secret struct {
	b []byte
}

// NewSecret wraps b. The Secret keeps b; callers must not reuse it.
func NewSecret(b []byte) Secret { return Secret{b: b} }

// Reveal returns the value. Call it only where the value is used (to
// authenticate to an upstream), never to log or return it.
func (s Secret) Reveal() []byte { return s.b }

// Len is the value's length in bytes.
func (s Secret) Len() int { return len(s.b) }

// String implements fmt.Stringer.
func (Secret) String() string { return Redacted }

// GoString implements fmt.GoStringer (%#v).
func (Secret) GoString() string { return Redacted }

// Format implements fmt.Formatter, covering every verb (%x, %q, %d …).
func (Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(Redacted)) }

// MarshalJSON implements json.Marshaler.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// MarshalText implements encoding.TextMarshaler (YAML, XML, map keys).
func (Secret) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }
