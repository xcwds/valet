package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// compilePattern turns an action pattern into a regular expression.
//
// Grammar:
//   - Literal characters match themselves (a-z 0-9 . _ -).
//   - * matches any run of characters within one dot-separated segment
//     (possibly empty): github.pr.* matches github.pr.comment but not
//     github.pr.review.submit; github.{repo,pr}.read* matches
//     github.repo.read and github.pr.read_files.
//   - ** as a whole segment matches one or more segments: github.** matches
//     every GitHub action.
//   - {a,b,c} matches one of the literal alternatives (no nesting, no
//     wildcards inside).
func compilePattern(p string) (*regexp.Regexp, error) {
	if p == "" {
		return nil, fmt.Errorf("empty action pattern")
	}
	var b strings.Builder
	b.WriteString("^")
	segs := strings.Split(p, ".")
	for i, seg := range segs {
		if i > 0 {
			b.WriteString(`\.`)
		}
		if seg == "" {
			return nil, fmt.Errorf("pattern %q: empty segment", p)
		}
		if seg == "**" {
			b.WriteString(`[a-z0-9_-]+(?:\.[a-z0-9_-]+)*`)
			continue
		}
		for j := 0; j < len(seg); j++ {
			c := seg[j]
			switch {
			case c == '*':
				if j+1 < len(seg) && seg[j+1] == '*' {
					return nil, fmt.Errorf("pattern %q: ** must be a whole segment", p)
				}
				b.WriteString(`[a-z0-9_-]*`)
			case c == '{':
				end := strings.IndexByte(seg[j:], '}')
				if end < 0 {
					return nil, fmt.Errorf("pattern %q: unclosed {", p)
				}
				alts := strings.Split(seg[j+1:j+end], ",")
				for k, a := range alts {
					if a == "" || strings.ContainsAny(a, "{}*.") || !literal.MatchString(a) {
						return nil, fmt.Errorf("pattern %q: bad alternative %q", p, a)
					}
					alts[k] = regexp.QuoteMeta(a)
				}
				b.WriteString("(?:" + strings.Join(alts, "|") + ")")
				j += end
			case c == '}' || c == ',':
				return nil, fmt.Errorf("pattern %q: unexpected %q", p, c)
			case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-':
				b.WriteByte(c)
			default:
				return nil, fmt.Errorf("pattern %q: unexpected %q", p, c)
			}
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

var literal = regexp.MustCompile(`^[a-z0-9_-]+$`)
