package cli

import (
	"bufio"
	"context"
	"encoding/json"
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
			var line struct{ Msg, Admin, Agent string }
			if json.Unmarshal(sc.Bytes(), &line) == nil && line.Msg == "started" {
				v := &liveValetd{
					dataDir: dataDir, admin: "http://" + line.Admin, agent: "http://" + line.Agent,
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

	// The agent port knows the session; there are no endpoints yet, so 403.
	if s := status(t, "GET", v.agent+"/mcp", "Bearer "+token); s != http.StatusForbidden {
		t.Errorf("agent with a valid session: %d, want 403", s)
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
		{"agent, session token", "GET", v.agent + "/mcp", "Bearer " + created.Token, 403},
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
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("git basic auth with a session token: %d, want 403", resp.StatusCode)
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
