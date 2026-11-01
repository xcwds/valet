package e2e

import (
	"bufio"
	"encoding/base64"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xcwds/valet/internal/audit"
)

// requireGit skips locally without git; CI must run these.
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("git not installed")
		}
		t.Skip("git not installed")
	}
}

// TestImplementerScenario is the M2 exit scenario (RFC, PoC plan): an
// implementer agent with nothing but its session token clones its
// repository, pushes its job branch and opens a pull request through
// Valet; pushing anywhere else is refused before GitHub sees it, alerted
// and audited.
func TestImplementerScenario(t *testing.T) {
	requireGit(t)
	v := Start(t)
	v.GitHub.HostRepo("xcwds/site")
	v.GitHub.HostRepo("xcwds/other")
	job := v.CreateJob(t, "implementer", "xcwds/site")
	other := v.CreateJob(t, "implementer", "xcwds/site")
	agent := v.MCP(t, job)
	work := filepath.Join(t.TempDir(), "site")

	// Clone, commit, push the job's branch.
	if out, err := v.Git(t, job, filepath.Dir(work), "clone", "-q", "https://github.com/xcwds/site", work); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	if out, err := v.Git(t, job, work, "commit", "-q", "--allow-empty", "-m", "Fix the greeting"); err != nil {
		t.Fatalf("commit: %v\n%s", err, out)
	}
	branch := "agent/" + job.ID + "/fix"
	head, _ := v.Git(t, job, work, "rev-parse", "HEAD")
	if out, err := v.Git(t, job, work, "push", "-q", "origin", "HEAD:refs/heads/"+branch); err != nil {
		t.Fatalf("push to the job branch: %v\n%s", err, out)
	}
	if got := v.GitHub.Ref("xcwds/site", "refs/heads/"+branch); got != strings.TrimSpace(head) {
		t.Fatalf("upstream %s = %q, want %s", branch, got, head)
	}

	// Open the pull request over MCP.
	isErr, text := agent.Call(t, "github_pr_create", map[string]any{
		"repo": "xcwds/site", "head": branch, "base": "main", "title": "Fix the greeting",
	})
	if isErr || !strings.Contains(text, `"number"`) {
		t.Fatalf("pr.create: %s", text)
	}
	if pulls := v.GitHub.Pulls(); len(pulls) != 1 || pulls[0]["head"] != branch || pulls[0]["base"] != "main" {
		t.Fatalf("pull requests upstream: %v", pulls)
	}

	// One narrowed token did all of it: only this repo, the implementer's permissions.
	grants := v.GitHub.Grants()
	if len(grants) != 1 {
		t.Fatalf("%d tokens minted, want 1", len(grants))
	}
	g := grants[0]
	want := map[string]string{"contents": "write", "pull_requests": "write", "checks": "read", "metadata": "read"}
	if !slices.Equal(g.Repos, []string{"xcwds/site"}) || !maps.Equal(g.Permissions, want) {
		t.Errorf("grant = %+v", g)
	}
	for _, c := range v.GitHub.GitCalls() {
		if c.Token != g.Token {
			t.Errorf("git %s %s used %q, not the job's narrowed token", c.Method, c.Path, c.Token)
		}
	}

	// Everything else is refused by Valet before GitHub sees it.
	pushesBefore := countPushes(v)
	mainBefore := v.GitHub.Ref("xcwds/site", "refs/heads/main")
	for name, args := range map[string][]string{
		"push to main":                 {"push", "origin", "HEAD:refs/heads/main"},
		"push to another job's branch": {"push", "origin", "HEAD:refs/heads/agent/" + other.ID + "/x"},
		"delete its own branch":        {"push", "origin", ":refs/heads/" + branch},
	} {
		out, err := v.Git(t, job, work, args...)
		if err == nil || !strings.Contains(out, "implementer/push-elsewhere") {
			t.Errorf("%s: err=%v\n%s", name, err, out)
		}
	}
	if out, err := v.Git(t, job, t.TempDir(), "clone", "-q", "https://github.com/xcwds/other", "o"); err == nil || !strings.Contains(out, "403") {
		t.Errorf("clone of a repo outside the job: err=%v\n%s", err, out)
	}
	if n := countPushes(v); n != pushesBefore {
		t.Errorf("%d refused pushes reached GitHub", n-pushesBefore)
	}
	if v.GitHub.Ref("xcwds/site", "refs/heads/main") != mainBefore || v.GitHub.Ref("xcwds/site", "refs/heads/"+branch) == "" {
		t.Error("an upstream ref changed")
	}

	// Each refusal is audited and alerted; the chain verifies.
	recs := v.Audit(t, job.ID)
	var denies int
	for _, r := range recs {
		if r.Decision == audit.Deny {
			denies++
		}
	}
	if denies != 4 {
		t.Errorf("%d audited denies, want 4", denies)
	}
	v.Ntfy.WaitFor(t, "git.push")
	v.Ntfy.WaitFor(t, "git.fetch")
	waitAlerts(t, v, 4)

	// The agent never saw GitHub's token: not in logs, audit, MCP replies or git's output.
	audited := v.MustCLI(t, "", "audit", "tail", "-n", "1000")
	for where, s := range map[string]string{"logs": v.Logs(), "audit": audited, "reply": text} {
		if strings.Contains(s, g.Token) {
			t.Errorf("the GitHub token leaked into the %s", where)
		}
	}
	v.VerifyAudit(t)
}

func countPushes(v *Valet) int {
	n := 0
	for _, c := range v.GitHub.GitCalls() {
		if c.Method == "POST" && strings.HasSuffix(c.Path, "/git-receive-pack") {
			n++
		}
	}
	return n
}

func waitAlerts(t *testing.T, v *Valet, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(v.Ntfy.Received()) < n {
		if time.Now().After(deadline) {
			t.Fatalf("%d alerts, want %d: %+v", len(v.Ntfy.Received()), n, v.Ntfy.Received())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A session token is refused everywhere once its job is revoked or has
// expired: MCP, git and egress alike.
func TestEndedJobsTokensAreRefusedEverywhere(t *testing.T) {
	t.Parallel() // waits a minute for expiry; let the rest run meanwhile
	requireGit(t)
	v := Start(t)
	v.GitHub.HostRepo("xcwds/site")

	revoked := v.CreateJob(t, "implementer", "xcwds/site")
	if out, err := v.Git(t, revoked, t.TempDir(), "clone", "-q", "https://github.com/xcwds/site", "s"); err != nil {
		t.Fatalf("clone before revoking: %v\n%s", err, out)
	}
	v.MustCLI(t, "", "job", "revoke", revoked.ID, "--reason", "demo")
	assertRefusedEverywhere(t, v, revoked, "job revoked")

	if testing.Short() {
		t.Skip("expiry takes a minute (the shortest TTL)")
	}
	expiring := v.CreateJobTTL(t, "implementer", time.Minute, "xcwds/site")
	if code := mcpStatus(t, v, expiring); code != http.StatusOK {
		t.Fatalf("MCP before expiry: %d", code)
	}
	time.Sleep(61 * time.Second)
	assertRefusedEverywhere(t, v, expiring, "job expired")
}

func assertRefusedEverywhere(t *testing.T, v *Valet, j Job, reason string) {
	t.Helper()
	if code := mcpStatus(t, v, j); code != http.StatusUnauthorized {
		t.Errorf("MCP: %d, want 401", code)
	}
	if out, err := v.Git(t, j, t.TempDir(), "clone", "-q", "https://github.com/xcwds/site", "s"); err == nil || !strings.Contains(out, "Authentication failed") {
		t.Errorf("git: err=%v\n%s", err, out)
	}
	if code := connectStatus(t, v, j); code != http.StatusProxyAuthRequired {
		t.Errorf("egress: %d, want 407", code)
	}
	var mcp, git, egress bool
	for _, r := range v.Audit(t, j.ID) {
		if r.Action == "session.authenticate" && r.Decision == audit.Deny && strings.Contains(string(r.Params), reason) {
			switch r.Interface {
			case audit.InterfaceMCP:
				mcp = true
			case audit.InterfaceGit:
				git = true
			case audit.InterfaceEgress:
				egress = true
			}
		}
	}
	if !mcp || !git || !egress {
		t.Errorf("refusals audited with %q: mcp=%v git=%v egress=%v", reason, mcp, git, egress)
	}
}

func mcpStatus(t *testing.T, v *Valet, j Job) int {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), "POST", v.Agent+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+j.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2025-06-18")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func connectStatus(t *testing.T, v *Valet, j Job) int {
	t.Helper()
	c, err := net.Dial("tcp", v.Egress)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	auth := base64.StdEncoding.EncodeToString([]byte("agent:" + j.Token))
	_, _ = io.WriteString(c, "CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org:443\r\nProxy-Authorization: Basic "+auth+"\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}
