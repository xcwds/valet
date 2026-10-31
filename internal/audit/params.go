package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// MaxStringLen is the longest string kept whole in params. Longer strings
// (PR bodies, diffs) are replaced by their length and SHA-256, so the log
// proves what was sent without storing all of it.
const MaxStringLen = 1024

// Redacted replaces values under sensitive keys.
const Redacted = "[redacted]"

// sensitiveKeys are redacted at any depth, whatever the caller marks, as a
// second line of defense behind connector ActionSpecs (#10). Matched
// case-insensitively, ignoring - and _.
var sensitiveKeys = map[string]bool{
	"authorization": true, "password": true, "passwd": true, "secret": true,
	"token": true, "accesstoken": true, "refreshtoken": true, "apikey": true,
	"privatekey": true, "clientsecret": true, "cookie": true, "setcookie": true,
	"sessiontoken": true, "credential": true, "credentials": true,
}

func normalizeKey(k string) string {
	return strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(k))
}

// canonicalParams turns params into canonical JSON: object keys sorted, keys
// in sensitive (top level) or sensitiveKeys (any depth) redacted, long strings
// truncated. Equal inputs always give identical bytes, which the hash chain
// depends on.
func canonicalParams(params any, sensitive []string) (json.RawMessage, error) {
	if params == nil {
		return json.RawMessage("{}"), nil
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("audit: params: %w", err)
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep numbers exactly as given
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("audit: params: %w", err)
	}
	top := map[string]bool{}
	for _, k := range sensitive {
		top[k] = true
	}
	if m, ok := v.(map[string]any); ok {
		for k := range m {
			if top[k] {
				m[k] = Redacted
			}
		}
	}
	v = scrub(v)
	out, err := json.Marshal(v) // maps marshal with sorted keys
	if err != nil {
		return nil, fmt.Errorf("audit: params: %w", err)
	}
	return out, nil
}

func scrub(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if sensitiveKeys[normalizeKey(k)] {
				t[k] = Redacted
				continue
			}
			t[k] = scrub(child)
		}
		return t
	case []any:
		for i, child := range t {
			t[i] = scrub(child)
		}
		return t
	case string:
		if len(t) > MaxStringLen {
			sum := sha256.Sum256([]byte(t))
			return map[string]any{"truncated": true, "length": len(t), "sha256": hex.EncodeToString(sum[:])}
		}
		return t
	default:
		return t
	}
}
