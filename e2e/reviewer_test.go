package e2e

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/xcwds/valet/internal/audit"
)

// TestReviewerScenario is the M1 exit scenario (RFC, PoC plan): a reviewer
// agent comments on a pull request, can't approve it, and can't merge it
// when told to by injected text. Only the comment reaches GitHub.
func TestReviewerScenario(t *testing.T) {
	v := Start(t)
	job := v.CreateJob(t, "reviewer", "xcwds/site")
	agent := v.MCP(t, job)

	// The reviewer is offered what its role could allow, and not merge.
	tools := agent.Tools(t)
	for _, want := range []string{"github_pr_comment", "github_pr_review_submit", "github_pr_read"} {
		if !slices.Contains(tools, want) {
			t.Errorf("%s not offered: %v", want, tools)
		}
	}
	if slices.Contains(tools, "github_pr_merge") {
		t.Errorf("merge offered to a reviewer: %v", tools)
	}

	// 1. A comment goes through, with a token narrowed to the job.
	if isErr, text := agent.Call(t, "github_pr_comment", map[string]any{"repo": "xcwds/site", "number": 7, "body": "LGTM apart from the typo."}); isErr {
		t.Fatalf("comment refused: %s", text)
	}
	grants := v.GitHub.Grants()
	if len(grants) != 1 {
		t.Fatalf("%d tokens minted, want 1", len(grants))
	}
	g := grants[0]
	wantPerms := map[string]string{"contents": "read", "pull_requests": "write", "checks": "read", "metadata": "read"}
	if !slices.Equal(g.Repos, []string{"xcwds/site"}) || !maps.Equal(g.Permissions, wantPerms) {
		t.Errorf("token grant = %+v, want only xcwds/site with %v", g, wantPerms)
	}
	posts := v.GitHub.ActionCalls()
	if n := len(posts); n != 2 || posts[1].Method != "POST" || posts[1].Path != "/repos/xcwds/site/issues/7/comments" ||
		posts[1].Body["body"] != "LGTM apart from the typo." || posts[1].Token != g.Token {
		t.Fatalf("upstream calls = %+v", posts)
	}

	// 2. Approving is denied before anything reaches GitHub, and alerts.
	isErr, text := agent.Call(t, "github_pr_review_submit", map[string]any{"repo": "xcwds/site", "number": 7, "event": "APPROVE"})
	if !isErr || !strings.Contains(text, "never-approve") {
		t.Errorf("approve: error=%v %q", isErr, text)
	}
	approve := v.Ntfy.WaitFor(t, "github.pr.review.submit")
	if approve.Priority != "high" || !strings.Contains(approve.Body, "rule: reviewer/never-approve") ||
		!strings.Contains(approve.Body, `"event":"APPROVE"`) || !strings.HasPrefix(approve.Click, "https://valet.test/audit/") {
		t.Errorf("approve alert = %+v", approve)
	}

	// 3. Prompt injection: text in the PR tells the agent to merge. It isn't
	// offered the tool, calls it anyway, and is denied the same way.
	isErr, text = agent.Call(t, "github_pr_merge", map[string]any{"repo": "xcwds/site", "number": 7, "method": "squash"})
	if !isErr || !strings.Contains(text, "never-merge") {
		t.Errorf("merge: error=%v %q", isErr, text)
	}
	v.Ntfy.WaitFor(t, "github.pr.merge")

	// Nothing but the comment (and its PR check) reached GitHub, and one token was minted.
	if calls := v.GitHub.ActionCalls(); len(calls) != 2 {
		t.Errorf("denied actions reached GitHub: %+v", calls)
	}
	if n := len(v.GitHub.Grants()); n != 1 {
		t.Errorf("%d tokens minted, want 1", n)
	}

	// The audit trail tells the story.
	recs := v.Audit(t, job.ID)
	expect := []struct{ action, decision, rule string }{
		{"github.pr.comment", audit.Allow, "reviewer/comment"},
		{"github.pr.review.submit", audit.Deny, "reviewer/never-approve"},
		{"github.pr.merge", audit.Deny, "reviewer/never-merge"},
	}
	for _, e := range expect {
		got := FindAudit(recs, e.action)
		if len(got) == 0 || got[0].Decision != e.decision || got[0].Rule != e.rule || got[0].Interface != "mcp" {
			t.Errorf("%s: audit = %+v, want %s by %s", e.action, got, e.decision, e.rule)
		}
	}
	if comment := FindAudit(recs, "github.pr.comment"); len(comment) != 2 || comment[1].UpstreamStatus != 201 {
		t.Errorf("comment result not audited: %+v", comment)
	}

	// No upstream token anywhere an operator or agent could see it.
	for where, s := range map[string]string{"logs": v.Logs(), "audit": v.MustCLI(t, "", "audit", "tail", "-n", "1000"), "reply": text} {
		if strings.Contains(s, g.Token) {
			t.Errorf("the GitHub token leaked into the %s", where)
		}
	}

	v.VerifyAudit(t)
}
