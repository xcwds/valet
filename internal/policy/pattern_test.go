package policy

import "testing"

func TestPatterns(t *testing.T) {
	cases := []struct {
		pattern string
		match   []string
		miss    []string
	}{
		{"github.pr.comment", []string{"github.pr.comment"}, []string{"github.pr.comments", "github.pr", "xgithub.pr.comment", "github.pr.comment.x"}},
		{"github.pr.*", []string{"github.pr.comment", "github.pr.read", "github.pr."[:10] + "x"}, []string{"github.pr.review.submit", "github.issue.read"}},
		{"github.{repo,pr,issue}.read*", []string{"github.repo.read", "github.pr.read", "github.issue.read", "github.pr.read_files"}, []string{"github.checks.read", "github.pr.diff", "github.repo.file.get", "github.pr.reads.x"}},
		{"github.**", []string{"github.pr.comment", "github.pr.review.submit", "github.x"}, []string{"github", "gitlab.pr.comment", "git.push"}},
		{"git.push", []string{"git.push"}, []string{"github.push", "git.pushx"}},
		{"*.read", []string{"github.read", "x.read"}, []string{"github.pr.read"}},
	}
	for _, c := range cases {
		re, err := compilePattern(c.pattern)
		if err != nil {
			t.Fatalf("%s: %v", c.pattern, err)
		}
		for _, s := range c.match {
			if !re.MatchString(s) {
				t.Errorf("%s should match %s", c.pattern, s)
			}
		}
		for _, s := range c.miss {
			if re.MatchString(s) {
				t.Errorf("%s should not match %s", c.pattern, s)
			}
		}
	}
}

func TestBadPatterns(t *testing.T) {
	for _, p := range []string{
		"", "github..pr", ".github", "github.", "github.{pr", "github.pr}", "github.{pr,}", "github.{p*}",
		"github.{a.b}", "github.pr**", "github.**x", "GitHub.pr", "github pr", "github.pr.(comment)", "github.pr.$",
	} {
		if _, err := compilePattern(p); err == nil {
			t.Errorf("%q compiled", p)
		}
	}
}
