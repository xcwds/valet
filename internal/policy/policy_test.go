package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/jobs"
	"github.com/xcwds/valet/internal/pipeline"
	"github.com/xcwds/valet/policies"
)

var ctx = context.Background()

func defaults(t *testing.T) *Policy {
	t.Helper()
	p, err := LoadFS("defaults", policies.Defaults)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func job(role string, repos ...string) jobs.Job {
	return jobs.Job{
		ID: "job-k3x9q2ma", Role: role, BranchPattern: "agent/job-k3x9q2ma/*",
		Grants: jobs.Grants{GitHub: &jobs.GitHubGrant{Repos: repos}}, ExpiresAt: time.Now().Add(time.Hour),
	}
}

// params decodes JSON the way the registry does (numbers as json.Number).
func params(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func decide(t *testing.T, p *Policy, j jobs.Job, action, ps string) pipeline.Decision {
	t.Helper()
	d, err := p.Decide(ctx, pipeline.Request{
		Job: j, Interface: "mcp", Action: action, Params: params(t, ps),
		Spec: connector.ActionSpec{Risk: connector.RiskMedium, Params: &jsonschema.Schema{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// The RFC's example rules, both outcomes each, through the default roles.
func TestDefaultRoles(t *testing.T) {
	p := defaults(t)
	rev := job("reviewer", "xcwds/site")
	imp := job("implementer", "xcwds/site")
	tri := job("triage", "xcwds/site")
	cases := []struct {
		name         string
		job          jobs.Job
		action, ps   string
		effect, rule string
		alert        bool
	}{
		{"reviewer comments in a review", rev, "github.pr.review.submit", `{"repo":"xcwds/site","number":7,"event":"COMMENT"}`, "allow", "reviewer/comment-or-request-changes", false},
		{"reviewer requests changes", rev, "github.pr.review.submit", `{"repo":"xcwds/site","number":7,"event":"REQUEST_CHANGES"}`, "allow", "reviewer/comment-or-request-changes", false},
		{"reviewer approves", rev, "github.pr.review.submit", `{"repo":"xcwds/site","number":7,"event":"APPROVE"}`, "deny", "reviewer/never-approve", true},
		{"reviewer reviews another repo", rev, "github.pr.review.submit", `{"repo":"other/repo","number":7,"event":"COMMENT"}`, "deny", "default", false},
		{"reviewer reads", rev, "github.pr.read", `{"repo":"xcwds/site","number":7}`, "allow", "reviewer/read", false},
		{"reviewer reads checks", rev, "github.checks.read", `{"repo":"xcwds/site","ref":"main"}`, "allow", "reviewer/read", false},
		{"reviewer reads another repo", rev, "github.issue.read", `{"repo":"other/repo","number":1}`, "deny", "default", false},
		{"reviewer comments", rev, "github.pr.comment", `{"repo":"xcwds/site","number":7,"body":"lgtm"}`, "allow", "reviewer/comment", false},
		{"reviewer merges", rev, "github.pr.merge", `{"repo":"xcwds/site","number":7}`, "deny", "reviewer/never-merge", true},
		{"reviewer pushes", rev, "git.push", `{"repo":"xcwds/site","refs":[]}`, "deny", "default", false},

		{"implementer pushes its branch", imp, "git.push", `{"repo":"xcwds/site","refs":[{"name":"refs/heads/agent/job-k3x9q2ma/fix","delete":false}]}`, "allow", "implementer/push-own-branch", false},
		{"implementer pushes main", imp, "git.push", `{"repo":"xcwds/site","refs":[{"name":"refs/heads/main","delete":false}]}`, "deny", "implementer/push-elsewhere", true},
		{"implementer pushes another job's branch", imp, "git.push", `{"repo":"xcwds/site","refs":[{"name":"refs/heads/agent/job-other/fix","delete":false}]}`, "deny", "implementer/push-elsewhere", true},
		{"implementer deletes its branch", imp, "git.push", `{"repo":"xcwds/site","refs":[{"name":"refs/heads/agent/job-k3x9q2ma/fix","delete":true}]}`, "deny", "implementer/push-elsewhere", true},
		{"implementer pushes one good and one bad ref", imp, "git.push", `{"repo":"xcwds/site","refs":[{"name":"refs/heads/agent/job-k3x9q2ma/fix","delete":false},{"name":"refs/heads/main","delete":false}]}`, "deny", "implementer/push-elsewhere", true},
		{"implementer pushes a prefix-confusable branch", imp, "git.push", `{"repo":"xcwds/site","refs":[{"name":"refs/heads/agent/job-k3x9q2ma-evil/fix","delete":false}]}`, "deny", "implementer/push-elsewhere", true},
		{"implementer pushes another repo", imp, "git.push", `{"repo":"other/repo","refs":[{"name":"refs/heads/agent/job-k3x9q2ma/fix","delete":false}]}`, "deny", "implementer/push-elsewhere", true},
		{"implementer opens a PR", imp, "github.pr.create", `{"repo":"xcwds/site","base":"main","head":"agent/job-k3x9q2ma/fix","title":"t"}`, "allow", "implementer/open-pr", false},
		{"implementer opens a PR into a release branch", imp, "github.pr.create", `{"repo":"xcwds/site","base":"release/1","head":"agent/job-k3x9q2ma/fix","title":"t"}`, "deny", "default", false},
		{"implementer opens a PR from someone's branch", imp, "github.pr.create", `{"repo":"xcwds/site","base":"main","head":"feature","title":"t"}`, "deny", "default", false},
		{"implementer merges", imp, "github.pr.merge", `{"repo":"xcwds/site","number":7}`, "require_approval", "implementer/merge-needs-a-human", true},
		{"implementer approves", imp, "github.pr.review.submit", `{"repo":"xcwds/site","number":7,"event":"APPROVE"}`, "deny", "default", false},

		{"triage comments on an issue", tri, "github.issue.comment", `{"repo":"xcwds/site","number":3,"body":"dup"}`, "allow", "triage/comment", false},
		{"triage reads a PR", tri, "github.pr.read", `{"repo":"xcwds/site","number":7}`, "deny", "default", false},
		{"triage pushes", tri, "git.push", `{"repo":"xcwds/site","refs":[]}`, "deny", "default", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := decide(t, p, c.job, c.action, c.ps)
			if d.Effect != c.effect || d.Rule != c.rule || d.Alert != c.alert {
				t.Errorf("got %s by %s (alert %v), want %s by %s (alert %v); reason %q", d.Effect, d.Rule, d.Alert, c.effect, c.rule, c.alert, d.Reason)
			}
		})
	}
}

func TestUnknownRoleDenies(t *testing.T) {
	d := decide(t, defaults(t), job("admin", "xcwds/site"), "github.pr.read", `{"repo":"xcwds/site"}`)
	if d.Effect != "deny" || d.Rule != "default" || !strings.Contains(d.Reason, "not defined") {
		t.Errorf("%+v", d)
	}
}

func load(t *testing.T, yamlText string) (*Policy, error) {
	t.Helper()
	return Load("test", map[string][]byte{"roles.yaml": []byte(yamlText)})
}

func mustLoad(t *testing.T, yamlText string) *Policy {
	t.Helper()
	p, err := load(t, yamlText)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFirstMatchWins(t *testing.T) {
	p := mustLoad(t, `
role: r
rules:
  - action: x.a
    decision: deny
  - action: x.a
    decision: allow
  - action: x.*
    decision: allow
`)
	if d := decide(t, p, job("r"), "x.a", `{}`); d.Effect != "deny" || d.Rule != "r#1" {
		t.Errorf("x.a: %+v", d)
	}
	if d := decide(t, p, job("r"), "x.b", `{}`); d.Effect != "allow" || d.Rule != "r#3" {
		t.Errorf("x.b: %+v", d)
	}
	if d := decide(t, p, job("r"), "y.a", `{}`); d.Effect != "deny" || d.Rule != "default" {
		t.Errorf("y.a: %+v", d)
	}
}

func TestEvaluationErrorsDenyAndNeverFallThrough(t *testing.T) {
	p := mustLoad(t, `
role: r
rules:
  - name: needs-repo
    action: x.a
    when: params.repo == 'a/b'
    decision: deny
  - name: permissive
    action: x.a
    decision: allow
  - name: number
    action: x.n
    when: params.n > 5
    decision: allow
  - name: not-bool
    action: x.d
    when: params.flag
    decision: allow
`)
	cases := map[string]struct{ action, ps, rule string }{
		"missing param":      {"x.a", `{}`, "r/needs-repo"},
		"non-boolean result": {"x.d", `{"flag":"yes"}`, "r/not-bool"},
		"string vs number":   {"x.n", `{"n":"6"}`, "r/number"},
	}
	for name, c := range cases {
		d := decide(t, p, job("r"), c.action, c.ps)
		if d.Effect != "deny" || d.Rule != c.rule || !strings.Contains(d.Reason, "could not be evaluated") {
			t.Errorf("%s: %+v", name, d)
		}
	}
	if d := decide(t, p, job("r"), "x.n", `{"n":6}`); d.Effect != "allow" {
		t.Errorf("integer param: %+v", d)
	}
	if d := decide(t, p, job("r"), "x.n", `{"n":6.5}`); d.Effect != "allow" {
		t.Errorf("CEL compares int and double; float param: %+v", d)
	}
	// CEL equality is heterogeneous: comparing a number with a string is
	// false, not an error, so the rule doesn't apply and the next one does.
	// Valet relies on params being validated against the action's schema
	// before policy sees them, so types match what rules expect.
	if d := decide(t, p, job("r"), "x.a", `{"repo":5}`); d.Effect != "allow" || d.Rule != "r/permissive" {
		t.Errorf("heterogeneous equality: %+v", d)
	}
}

func TestCostLimitDenies(t *testing.T) {
	p := mustLoad(t, `
role: r
rules:
  - action: x.a
    when: params.items.all(a, params.items.all(b, params.items.all(c, a + b + c != 'zzz')))
    decision: allow
`)
	items := make([]string, 200)
	for i := range items {
		items[i] = "x"
	}
	b, _ := json.Marshal(map[string]any{"items": items})
	d := decide(t, p, job("r"), "x.a", string(b))
	if d.Effect != "deny" || !strings.Contains(d.Reason, "could not be evaluated") {
		t.Errorf("an expensive condition was not cut off: %+v", d)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]string{
		"unknown key":       "role: r\nrules:\n  - action: x.a\n    decision: allow\n    verdict: deny\n",
		"bad decision":      "role: r\nrules:\n  - action: x.a\n    decision: permit\n",
		"bad pattern":       "role: r\nrules:\n  - action: x..a\n    decision: allow\n",
		"bad CEL":           "role: r\nrules:\n  - action: x.a\n    when: params.repo ==\n    decision: allow\n",
		"unknown job field": "role: r\nrules:\n  - action: x.a\n    when: params.repo in job.repoz\n    decision: allow\n",
		"unknown variable":  "role: r\nrules:\n  - action: x.a\n    when: request.repo == 'a'\n    decision: allow\n",
		"non-bool when":     "role: r\nrules:\n  - action: x.a\n    when: job.id\n    decision: allow\n",
		"bad role name":     "role: Admin\nrules:\n  - action: x.a\n    decision: allow\n",
		"no rules":          "role: r\nrules: []\n",
		"duplicate role":    "role: r\nrules:\n  - action: x.a\n    decision: allow\n---\nrole: r\nrules:\n  - action: x.b\n    decision: allow\n",
		"duplicate name":    "role: r\nrules:\n  - name: a\n    action: x.a\n    decision: allow\n  - name: a\n    action: x.b\n    decision: allow\n",
		"empty":             "",
	}
	for name, y := range cases {
		if _, err := load(t, y); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestLoadReportsEveryError(t *testing.T) {
	_, err := load(t, "role: r\nrules:\n  - action: x..a\n    decision: allow\n  - action: x.b\n    decision: permit\n")
	if err == nil || !strings.Contains(err.Error(), "r#1") || !strings.Contains(err.Error(), "r#2") {
		t.Fatalf("err = %v, want both rules reported", err)
	}
}

func TestHasRoleAndUnmatched(t *testing.T) {
	p := defaults(t)
	if strings.Join(p.Roles(), ",") != "implementer,reviewer,triage" || !p.HasRole("reviewer") || p.HasRole("root") {
		t.Errorf("roles = %v", p.Roles())
	}
	un := p.Unmatched([]string{"github.pr.read"})
	if len(un) == 0 || strings.Contains(strings.Join(un, " "), "reviewer/read ") {
		t.Errorf("unmatched = %v", un)
	}
}

func TestDefaultsFileIsValidYAML(t *testing.T) {
	b, err := policies.Defaults.ReadFile("roles.yaml")
	if err != nil || !bytes.Contains(b, []byte("role: reviewer")) {
		t.Fatalf("%v", err)
	}
}
