package gitproxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Limits on the receive-pack command list, read before policy runs.
const (
	// MaxCommandBytes caps the pkt-lines read before the flush. Each ref
	// line is ~100 bytes, so this fits a thousand refs with room to spare.
	MaxCommandBytes = 256 << 10
	// MaxRefs caps how many refs one push may update.
	MaxRefs = 1000
)

// maxPayload is the largest pkt-line payload (65520 bytes with the header).
const maxPayload = 65516

// ErrMalformed marks a command list Valet refuses to interpret.
var ErrMalformed = errors.New("malformed push commands")

// RefUpdate is one ref a push changes.
type RefUpdate struct {
	Name   string `json:"name"`
	Old    string `json:"old"`
	New    string `json:"new"`
	Delete bool   `json:"delete"`
}

// Commands is the parsed head of a git-receive-pack request.
type Commands struct {
	Refs []RefUpdate
	Caps []string
	// Raw is every byte read, through the flush packet, to be sent
	// upstream unchanged ahead of the rest of the body.
	Raw []byte
}

// HasCap reports whether the client asked for a capability.
func (c *Commands) HasCap(name string) bool {
	for _, cp := range c.Caps {
		if cp == name || strings.HasPrefix(cp, name+"=") {
			return true
		}
	}
	return false
}

// ParseCommands reads the command list of a git-receive-pack request:
// optional "shallow" lines, then "<old> <new> <ref>" lines (the first with
// NUL and capabilities), then a flush packet. It reads nothing past the
// flush, so push options and the pack stay in r. Anything unexpected,
// oversized or truncated is ErrMalformed: the caller denies.
func ParseCommands(r io.Reader) (*Commands, error) {
	c := &Commands{}
	for {
		payload, flush, err := readPkt(r, &c.Raw)
		if err != nil {
			return nil, err
		}
		if flush {
			break
		}
		line := strings.TrimSuffix(string(payload), "\n")
		if rest, ok := strings.CutPrefix(line, "shallow "); ok && len(c.Refs) == 0 {
			if !isSHA(rest) {
				return nil, fmt.Errorf("%w: bad shallow line", ErrMalformed)
			}
			continue
		}
		if strings.HasPrefix(line, "push-cert") {
			return nil, fmt.Errorf("%w: signed pushes are not supported", ErrMalformed)
		}
		if len(c.Refs) == 0 {
			cmd, caps, hasCaps := strings.Cut(line, "\x00")
			if hasCaps {
				c.Caps = strings.Fields(caps)
			}
			line = cmd
		} else if strings.Contains(line, "\x00") {
			return nil, fmt.Errorf("%w: NUL in a command", ErrMalformed)
		}
		u, err := parseCommand(line)
		if err != nil {
			return nil, err
		}
		if len(c.Refs) == MaxRefs {
			return nil, fmt.Errorf("%w: more than %d refs", ErrMalformed, MaxRefs)
		}
		c.Refs = append(c.Refs, u)
	}
	if len(c.Refs) == 0 {
		return nil, fmt.Errorf("%w: no ref updates", ErrMalformed)
	}
	return c, nil
}

// readPkt reads one pkt-line, appending its bytes to raw. It returns the
// payload, or flush for "0000".
func readPkt(r io.Reader, raw *[]byte) (payload []byte, flush bool, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, false, fmt.Errorf("%w: truncated", ErrMalformed)
	}
	n, err := strconv.ParseUint(string(hdr[:]), 16, 16)
	if err != nil || bytes.ContainsAny(hdr[:], "+-") {
		return nil, false, fmt.Errorf("%w: bad pkt-line length", ErrMalformed)
	}
	*raw = append(*raw, hdr[:]...)
	switch {
	case n == 0:
		return nil, true, nil
	case n < 5 || n > maxPayload+4: // 0001-0004 are special or empty: not valid here
		return nil, false, fmt.Errorf("%w: bad pkt-line length", ErrMalformed)
	}
	if len(*raw)+int(n)-4 > MaxCommandBytes {
		return nil, false, fmt.Errorf("%w: command list over %d bytes", ErrMalformed, MaxCommandBytes)
	}
	payload = make([]byte, n-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, false, fmt.Errorf("%w: truncated", ErrMalformed)
	}
	*raw = append(*raw, payload...)
	return payload, false, nil
}

func parseCommand(line string) (RefUpdate, error) {
	f := strings.Split(line, " ")
	if len(f) != 3 || !isSHA(f[0]) || !isSHA(f[1]) || len(f[0]) != len(f[1]) {
		return RefUpdate{}, fmt.Errorf("%w: bad command", ErrMalformed)
	}
	if !validRefName(f[2]) {
		return RefUpdate{}, fmt.Errorf("%w: bad ref name", ErrMalformed)
	}
	zero := strings.Repeat("0", len(f[1]))
	if f[0] == zero && f[1] == zero {
		return RefUpdate{}, fmt.Errorf("%w: bad command", ErrMalformed)
	}
	return RefUpdate{Name: f[2], Old: f[0], New: f[1], Delete: f[1] == zero}, nil
}

// isSHA accepts SHA-1 or SHA-256 object names in lowercase hex.
func isSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validRefName applies git check-ref-format's rules to a full ref name,
// so policy patterns can't be dodged with a name git itself would refuse.
func validRefName(s string) bool {
	if len(s) > 1024 || !strings.HasPrefix(s, "refs/") || strings.HasSuffix(s, "/") ||
		strings.HasSuffix(s, ".") || strings.Contains(s, "..") || strings.Contains(s, "@{") ||
		strings.Contains(s, "//") || s == "@" {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f || strings.ContainsRune(" ~^:?*[\\", c) {
			return false
		}
	}
	for _, comp := range strings.Split(s, "/") {
		if comp == "" || strings.HasPrefix(comp, ".") || strings.HasSuffix(comp, ".lock") {
			return false
		}
	}
	return true
}

// pkt frames payload as a pkt-line.
func pkt(payload string) string { return fmt.Sprintf("%04x%s", len(payload)+4, payload) }
