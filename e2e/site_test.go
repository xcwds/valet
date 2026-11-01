package e2e

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	refRe      = regexp.MustCompile(`(?:href|src)="([^"]+)"`)
	externalRe = regexp.MustCompile(`^https?://`)
)

// The site (valet.xcwds.com) links resolve, and it loads nothing from
// elsewhere: no scripts at all, and stylesheets and icons only from itself.
// Plain links out (to the repository) are fine.
func TestSiteIsSelfContained(t *testing.T) {
	root := filepath.Join("..", "site")
	pages, _ := filepath.Glob(filepath.Join(root, "*.html"))
	sub, _ := filepath.Glob(filepath.Join(root, "*", "*.html"))
	pages = append(pages, sub...)
	if len(pages) < 3 {
		t.Fatalf("found %d pages", len(pages))
	}
	for _, page := range pages {
		b, err := os.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		html := string(b)
		if strings.Contains(html, "<script") || strings.Contains(html, "@import") {
			t.Errorf("%s: scripts or imports", page)
		}
		for _, line := range strings.Split(html, "\n") {
			if (strings.Contains(line, "<link") || strings.Contains(line, "<img")) && strings.Contains(line, "://") {
				t.Errorf("%s: loads from elsewhere: %s", page, strings.TrimSpace(line))
			}
		}
		for _, m := range refRe.FindAllStringSubmatch(html, -1) {
			ref := m[1]
			if externalRe.MatchString(ref) {
				continue
			}
			var target string
			if strings.HasPrefix(ref, "/") {
				target = filepath.Join(root, ref)
			} else {
				target = filepath.Join(filepath.Dir(page), ref)
			}
			if strings.HasSuffix(ref, "/") || ref == "./" {
				target = filepath.Join(target, "index.html")
			}
			if _, err := os.Stat(target); err != nil {
				t.Errorf("%s: broken link %q", page, ref)
			}
		}
	}
	css, _ := os.ReadFile(filepath.Join(root, "style.css"))
	if strings.Contains(string(css), "url(") || strings.Contains(string(css), "@import") {
		t.Error("style.css loads something")
	}
}
