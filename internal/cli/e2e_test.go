package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// liveValetd is a running valetd for end-to-end tests.
type liveValetd struct {
	dataDir string
	admin   string // http://host:port
	agent   string
	egress  string            // host:port
	env     map[string]string // what the CLI on the same host would have
	stop    func() int
}

func startValetd(t *testing.T) *liveValetd {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "data")
	path := writeFile(t, "data_dir: "+dataDir+"\nlisten: {admin: '127.0.0.1:0', agent: '127.0.0.1:0', egress: '127.0.0.1:0'}\n")
	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- Run(ctx, []string{"valetd", "--config", path}, IO{Stdout: &stdout, Stderr: &stderr, Getenv: keyEnv})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		sc := bufio.NewScanner(strings.NewReader(stdout.String()))
		for sc.Scan() {
			var line struct{ Msg, Admin, Agent, Egress string }
			if json.Unmarshal(sc.Bytes(), &line) == nil && line.Msg == "started" {
				v := &liveValetd{
					dataDir: dataDir, admin: "http://" + line.Admin, agent: "http://" + line.Agent, egress: line.Egress,
					env: map[string]string{"VALET_DATA_DIR": dataDir, "VALET_ADMIN_URL": "http://" + line.Admin},
				}
				stopped := false
				v.stop = func() int {
					if stopped {
						return ExitOK
					}
					stopped = true
					cancel()
					return <-done
				}
				t.Cleanup(func() { v.stop() })
				return v
			}
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("valetd did not start: %q", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (v *liveValetd) cli(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut syncBuffer
	code := Run(context.Background(), append([]string{"valet"}, args...), IO{
		Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errOut,
		Getenv: func(k string) string { return v.env[k] },
	})
	return code, out.String(), errOut.String()
}

func status(t *testing.T, method, url, auth string) int {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, url, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestM0Exit is the milestone's exit criterion: `valet job create` returns a
// token and the create is audited.
func TestM0Exit(t *testing.T) {
	v := startValetd(t)

	code, out, errOut := v.cli(t, "", "job", "create", "--role", "implementer", "--repo", "xcwds/site", "--ttl", "2h", "--json")
	if code != ExitOK {
		t.Fatalf("job create: %d %q", code, errOut)
	}
	var created struct {
		Job struct {
			ID            string `json:"id"`
			BranchPattern string `json:"branch_pattern"`
		} `json:"job"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(out), &created); err != nil || !strings.HasPrefix(created.Token, "vlt_sess_") {
		t.Fatalf("output %q (%v)", out, err)
	}

	code, out, _ = v.cli(t, "", "audit", "tail", "--job", created.Job.ID)
	if code != ExitOK || !strings.Contains(out, `"action":"job.create"`) || !strings.Contains(out, created.Job.ID) {
		t.Fatalf("job.create not audited: %q", out)
	}
	if strings.Contains(out, created.Token) {
		t.Fatal("token in the audit log")
	}
}

func TestJobLifecycleThroughTheCLI(t *testing.T) {
	v := startValetd(t)
	code, out, errOut := v.cli(t, "", "job", "create", "--role", "reviewer", "--repo", "xcwds/site")
	if code != ExitOK || !strings.Contains(out, "token:   vlt_sess_") || !strings.Contains(errOut, "shown once") {
		t.Fatalf("create: %d %q %q", code, out, errOut)
	}
	id := strings.Fields(strings.SplitN(out, "\n", 2)[0])[1]
	token := ""
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "token:" {
			token = f[1]
		}
	}

	if code, out, _ := v.cli(t, "", "job", "list"); code != ExitOK || !strings.Contains(out, id) || !strings.Contains(out, "active") {
		t.Fatalf("list: %d %q", code, out)
	}
	if code, out, _ := v.cli(t, "", "job", "show", id); code != ExitOK || !strings.Contains(out, `"role": "reviewer"`) {
		t.Fatalf("show: %d %q", code, out)
	}

	// The agent port knows the session: it reaches MCP, which takes only
	// POST (405 rather than 401).
	if s := status(t, "GET", v.agent+"/mcp", "Bearer "+token); s != http.StatusMethodNotAllowed {
		t.Errorf("agent with a valid session: %d, want 405", s)
	}
	// Flags after the positional argument work too.
	if code, _, errOut := v.cli(t, "", "job", "revoke", id, "--reason", "test"); code != ExitOK {
		t.Fatalf("revoke: %d %q", code, errOut)
	}
	if s := status(t, "GET", v.agent+"/mcp", "Bearer "+token); s != http.StatusUnauthorized {
		t.Errorf("agent after revoke: %d, want 401", s)
	}
	if code, _, errOut := v.cli(t, "", "job", "revoke", id); code != ExitError || !strings.Contains(errOut, "not active") {
		t.Errorf("second revoke: %d %q", code, errOut)
	}
	for _, trick := range []string{"../secrets", "job-aaaaaaaa/../../secrets", "%2e%2e"} {
		if code, out, _ := v.cli(t, "", "job", "show", trick); code != ExitUsage || out != "" {
			t.Errorf("show %q: %d %q", trick, code, out)
		}
	}
	if code, _, errOut := v.cli(t, "", "job", "show", "job-aaaaaaaa"); code != ExitError || !strings.Contains(errOut, "not found") {
		t.Errorf("unknown job: %d %q", code, errOut)
	}
}

func TestTokensStayOnTheirPort(t *testing.T) {
	v := startValetd(t)
	adminTok, err := os.ReadFile(filepath.Join(v.dataDir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	admin := strings.TrimSpace(string(adminTok))
	_, out, _ := v.cli(t, "", "job", "create", "--role", "reviewer", "--json")
	var created struct{ Token string }
	_ = json.Unmarshal([]byte(out), &created)

	cases := []struct {
		name, method, url, auth string
		want                    int
	}{
		{"admin API, admin token", "GET", v.admin + "/api/jobs", "Bearer " + admin, 200},
		{"admin API, session token", "GET", v.admin + "/api/jobs", "Bearer " + created.Token, 401},
		{"admin API, no token", "GET", v.admin + "/api/jobs", "", 401},
		{"admin API, basic auth", "GET", v.admin + "/api/jobs", "Basic " + admin, 401},
		{"agent, admin token", "GET", v.agent + "/mcp", "Bearer " + admin, 401},
		{"agent, no token", "GET", v.agent + "/mcp", "", 401},
		{"agent, session token", "GET", v.agent + "/mcp", "Bearer " + created.Token, 405}, // past auth; MCP is POST-only
		{"health needs no token", "GET", v.admin + "/healthz", "", 200},
	}
	for _, c := range cases {
		if got := status(t, c.method, c.url, c.auth); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}

	// git sends the session token as the basic-auth password.
	req, _ := http.NewRequestWithContext(context.Background(), "GET", v.agent+"/git/github/xcwds/site.git/info/refs", nil)
	req.SetBasicAuth("x-access-token", created.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound { // past auth; the git proxy is #17
		t.Errorf("git basic auth with a session token: %d, want 404", resp.StatusCode)
	}

	_, out, _ = v.cli(t, "", "audit", "tail", "--decision", "deny", "-n", "100")
	for _, want := range []string{`"action":"admin.authenticate"`, `"action":"session.authenticate"`} {
		if !strings.Contains(out, want) {
			t.Errorf("denies not audited: missing %s", want)
		}
	}
	if strings.Contains(out, admin) || strings.Contains(out, created.Token) {
		t.Error("a token reached the audit log")
	}
}

func TestSecretsThroughTheCLI(t *testing.T) {
	v := startValetd(t)
	if code, out, errOut := v.cli(t, "the-value\n", "secrets", "set", "github/app-key"); code != ExitOK || !strings.Contains(out, "9 bytes") {
		t.Fatalf("set: %d %q %q", code, out, errOut)
	}
	code, out, _ := v.cli(t, "", "secrets", "list")
	if code != ExitOK || !strings.Contains(out, "github/app-key") || strings.Contains(out, "the-value") {
		t.Fatalf("list: %d %q", code, out)
	}
	if code, _, errOut := v.cli(t, "", "secrets", "delete", "github/app-key"); code != ExitOK {
		t.Fatalf("delete: %d %q", code, errOut)
	}
	if code, _, errOut := v.cli(t, "", "secrets", "delete", "github/app-key"); code != ExitError || !strings.Contains(errOut, "not found") {
		t.Errorf("second delete: %d %q", code, errOut)
	}
	for _, bad := range []string{"a/../b", "a//b", "a/", "./a"} {
		if code, _, _ := v.cli(t, "v", "secrets", "set", bad); code != ExitUsage {
			t.Errorf("set %q: code %d", bad, code)
		}
	}
	if code, _, _ := v.cli(t, "", "secrets", "set", "empty"); code != ExitUsage {
		t.Error("empty value accepted")
	}
}

func TestAdminTokenFromEnvAndFile(t *testing.T) {
	v := startValetd(t)
	path := filepath.Join(v.dataDir, "admin.token")
	b, _ := os.ReadFile(path)
	tok := strings.TrimSpace(string(b))

	v.env = map[string]string{"VALET_ADMIN_URL": v.env["VALET_ADMIN_URL"], "VALET_ADMIN_TOKEN": tok}
	if code, _, errOut := v.cli(t, "", "job", "list"); code != ExitOK {
		t.Fatalf("token from env: %d %q", code, errOut)
	}
	v.env = map[string]string{"VALET_ADMIN_URL": v.env["VALET_ADMIN_URL"]}
	if code, _, errOut := v.cli(t, "", "job", "list", "--token-file", path); code != ExitOK {
		t.Fatalf("token from file: %d %q", code, errOut)
	}
	v.env["VALET_ADMIN_TOKEN"] = "vlt_sess_" + strings.Repeat("a", 52)
	if code, _, errOut := v.cli(t, "", "job", "list"); code != ExitError || !strings.Contains(errOut, "not a vlt_admin_ token") {
		t.Errorf("session token as admin: %d %q", code, errOut)
	}
}

func TestResetToken(t *testing.T) {
	v := startValetd(t)
	path := filepath.Join(v.dataDir, "admin.token")
	old, _ := os.ReadFile(path)

	if code, _, errOut := v.cli(t, "", "admin", "reset-token"); code != ExitError || !strings.Contains(errOut, "stop valetd first") {
		t.Fatalf("reset while running: %d %q", code, errOut)
	}
	if code := v.stop(); code != ExitOK {
		t.Fatal(code)
	}
	if code, out, errOut := v.cli(t, "", "admin", "reset-token"); code != ExitOK || !strings.Contains(out, path) {
		t.Fatalf("reset: %d %q %q", code, out, errOut)
	}
	fresh, _ := os.ReadFile(path)
	if string(fresh) == string(old) {
		t.Fatal("token unchanged")
	}
}

func TestAgentPortThrottlesFloods(t *testing.T) {
	v := startValetd(t)
	var codes []int
	for range 15 {
		codes = append(codes, status(t, "GET", v.agent+"/mcp", "Bearer vlt_sess_bogus"))
	}
	want := "[401 401 401 401 401 401 401 401 401 401 429 429 429 429 429]"
	if fmt.Sprint(codes) != want {
		t.Fatalf("codes = %v, want %s", codes, want)
	}
	_, out, _ := v.cli(t, "", "audit", "tail", "--decision", "deny", "-n", "100")
	if n := strings.Count(out, "session.authenticate"); n != 11 {
		t.Errorf("%d audited failures for 15 attempts, want 11", n)
	}
}

// An MCP client reaches the tools through a real valetd, with nothing but
// its session token. No connectors are configured, so the list is empty and
// any call is denied and audited.
func TestMCPThroughValetd(t *testing.T) {
	v := startValetd(t)
	_, out, _ := v.cli(t, "", "job", "create", "--role", "reviewer", "--repo", "xcwds/site", "--json")
	var created struct{ Token string }
	_ = json.Unmarshal([]byte(out), &created)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"github_pr_merge","arguments":{"repo":"xcwds/site","number":1}}}`
	req, _ := http.NewRequestWithContext(context.Background(), "POST", v.agent+"/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+created.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2025-06-18")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"isError":true`) || !strings.Contains(string(b), "unknown action") {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	_, out, _ = v.cli(t, "", "audit", "tail", "--decision", "deny")
	// No connector offers it, so the record names the tool as called.
	if !strings.Contains(out, `"action":"github_pr_merge"`) || !strings.Contains(out, `"interface":"mcp"`) {
		t.Errorf("the call was not audited: %s", out)
	}
}

// Charon answers on valetd's egress port: anonymous CONNECTs are
// challenged, and with no allowlist configured a job's CONNECT is denied
// and audited.
func TestEgressThroughValetd(t *testing.T) {
	v := startValetd(t)
	_, out, _ := v.cli(t, "", "job", "create", "--role", "implementer", "--repo", "xcwds/site", "--json")
	var created struct{ Token string }
	_ = json.Unmarshal([]byte(out), &created)

	connect := func(auth string) int {
		t.Helper()
		c, err := net.Dial("tcp", v.egress)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		req := "CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org:443\r\n"
		if auth != "" {
			req += "Proxy-Authorization: " + auth + "\r\n"
		}
		_, _ = io.WriteString(c, req+"\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if s := connect(""); s != http.StatusProxyAuthRequired {
		t.Errorf("anonymous: %d, want 407", s)
	}
	if s := connect("Bearer " + created.Token); s != http.StatusForbidden {
		t.Errorf("no allowlist: %d, want 403", s)
	}
	_, out, _ = v.cli(t, "", "audit", "tail", "--decision", "deny")
	if !strings.Contains(out, `"action":"egress.connect"`) || !strings.Contains(out, `"rule":"egress/allowlist"`) {
		t.Errorf("the refused CONNECT was not audited: %s", out)
	}
}
