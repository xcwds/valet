package egress

import "strings"

// allowlist matches host names against exact names and "*.suffix"
// patterns. A suffix pattern matches subdomains only, not the bare suffix.
type allowlist struct {
	exact    map[string]bool
	suffixes []string // ".pythonhosted.org"
}

func newAllowlist(patterns []string) allowlist {
	a := allowlist{exact: map[string]bool{}}
	for _, p := range patterns {
		if s, ok := strings.CutPrefix(p, "*"); ok {
			a.suffixes = append(a.suffixes, s)
		} else {
			a.exact[p] = true
		}
	}
	return a
}

// match returns the pattern that allows host, or "".
func (a allowlist) match(host string) string {
	if a.exact[host] {
		return host
	}
	for _, s := range a.suffixes {
		if strings.HasSuffix(host, s) && len(host) > len(s) {
			return "*" + s
		}
	}
	return ""
}
