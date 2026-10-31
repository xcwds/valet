package policy

import (
	"encoding/json"
	"strings"
)

// celValue converts decoded JSON (with json.Number) into values CEL knows:
// integers as int64, other numbers as float64, recursively.
func celValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = celValue(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = celValue(x)
		}
		return out
	case json.Number:
		if !strings.ContainsAny(string(t), ".eE") {
			if n, err := t.Int64(); err == nil {
				return n
			}
		}
		f, _ := t.Float64()
		return f
	case nil:
		return nil
	default:
		return t
	}
}
