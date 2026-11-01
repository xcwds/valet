package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/cli"
	"github.com/xcwds/valet/internal/secrets"
)

// Valet is a running valetd wired to a fake GitHub and an ntfy sink.
type Valet struct {
	DataDir string
	Admin   string // http://host:port
	Agent   string
	GitHub  *FakeGitHub
	Ntfy    *NtfySink

	env  map[string]string
	logs *syncBuffer
}

// Start runs valetd in-process with a temporary data directory, a fresh
// master key, the built-in roles, the GitHub connector pointed at a fake,
// and alerts going to an ntfy sink. It stops when the test ends.
func Start(t *testing.T) *Valet {
	t.Helper()
	dir := t.TempDir()
	key, err := secrets.NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	gh := NewFakeGitHub(t)
	ntfy := NewNtfySink(t)
	v := &Valet{DataDir: filepath.Join(dir, "data"), GitHub: gh, Ntfy: ntfy, logs: &syncBuffer{}}

	connectors := write(t, dir, "connectors.yaml", fmt.Sprintf(
		"github:\n  app_id: %q\n  installation_id: %d\n  private_key_secret: github/app-key\n  api_url: %s\n",
		appID, installationID, gh.URL()))
	config := write(t, dir, "valet.yaml", fmt.Sprintf(`data_dir: %s
listen: {admin: '127.0.0.1:0', agent: '127.0.0.1:0', egress: '127.0.0.1:0'}
connectors: %s
alerts:
  on_deny: all
  ui_url: https://valet.test
  ntfy: {url: %s/valet}
`, v.DataDir, connectors, ntfy.URL()))

	env := map[string]string{secrets.DefaultKeyEnv: key}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	var stderr syncBuffer
	go func() {
		done <- cli.Run(ctx, []string{"valetd", "--config", config}, cli.IO{
			Stdout: v.logs, Stderr: &stderr, Getenv: func(k string) string { return env[k] },
		})
	}()
	t.Cleanup(func() {
		cancel()
		if code := <-done; code != cli.ExitOK {
			t.Errorf("valetd exited %d: %s", code, stderr.String())
		}
	})

	deadline := time.Now().Add(10 * time.Second)
	for v.Admin == "" {
		sc := bufio.NewScanner(strings.NewReader(v.logs.String()))
		for sc.Scan() {
			var line struct{ Msg, Admin, Agent string }
			if json.Unmarshal(sc.Bytes(), &line) == nil && line.Msg == "started" {
				v.Admin, v.Agent = "http://"+line.Admin, "http://"+line.Agent
			}
		}
		if v.Admin != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("valetd did not start: %s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	v.env = map[string]string{"VALET_DATA_DIR": v.DataDir, "VALET_ADMIN_URL": v.Admin}
	v.MustCLI(t, string(gh.PrivateKeyPEM()), "secrets", "set", "github/app-key")
	return v
}

// CLI runs `valet ARGS...` against this valetd, as an operator on the same
// host would (admin token from the data directory).
func (v *Valet) CLI(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut syncBuffer
	code = cli.Run(context.Background(), append([]string{"valet"}, args...), cli.IO{
		Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errOut,
		Getenv: func(k string) string { return v.env[k] },
	})
	return code, out.String(), errOut.String()
}

// MustCLI is CLI that fails the test on a non-zero exit.
func (v *Valet) MustCLI(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	code, out, errOut := v.CLI(t, stdin, args...)
	if code != cli.ExitOK {
		t.Fatalf("valet %s: exit %d: %s", strings.Join(args, " "), code, errOut)
	}
	return out
}

// Job is a created job and its session token.
type Job struct {
	ID    string
	Token string
}

// CreateJob creates a job through the CLI.
func (v *Valet) CreateJob(t *testing.T, role string, repos ...string) Job {
	t.Helper()
	args := []string{"job", "create", "--role", role, "--json"}
	for _, r := range repos {
		args = append(args, "--repo", r)
	}
	var created struct {
		Job   struct{ ID string } `json:"job"`
		Token string              `json:"token"`
	}
	if err := json.Unmarshal([]byte(v.MustCLI(t, "", args...)), &created); err != nil || created.Token == "" {
		t.Fatalf("job create: %v", err)
	}
	return Job{ID: created.Job.ID, Token: created.Token}
}

// MCP connects an MCP client holding nothing but the job's session token.
func (v *Valet) MCP(t *testing.T, j Job) *Agent {
	t.Helper()
	c := sdk.NewClient(&sdk.Implementation{Name: "e2e-agent", Version: "1"}, nil)
	cs, err := c.Connect(context.Background(), &sdk.StreamableClientTransport{
		Endpoint:             v.Agent + "/mcp",
		HTTPClient:           &http.Client{Transport: bearer{j.Token, http.DefaultTransport}},
		MaxRetries:           -1,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("mcp connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return &Agent{cs: cs}
}

// Agent is an MCP client session.
type Agent struct{ cs *sdk.ClientSession }

// Tools lists the tool names offered.
func (a *Agent) Tools(t *testing.T) []string {
	t.Helper()
	res, err := a.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	slices.Sort(names)
	return names
}

// Call calls a tool and returns whether it failed and its text.
func (a *Agent) Call(t *testing.T, tool string, args map[string]any) (isError bool, text string) {
	t.Helper()
	res, err := a.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", tool, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return res.IsError, b.String()
}

// Audit returns the job's audit records, oldest first.
func (v *Valet) Audit(t *testing.T, jobID string) []audit.Record {
	t.Helper()
	out := v.MustCLI(t, "", "audit", "tail", "--job", jobID, "-n", "1000")
	var recs []audit.Record
	for line := range strings.Lines(out) {
		var r audit.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("audit line %q: %v", line, err)
		}
		recs = append(recs, r)
	}
	return recs
}

// FindAudit returns the records for one action.
func FindAudit(recs []audit.Record, action string) []audit.Record {
	var out []audit.Record
	for _, r := range recs {
		if r.Action == action {
			out = append(out, r)
		}
	}
	return out
}

// VerifyAudit checks the whole hash chain with `valet audit verify`.
func (v *Valet) VerifyAudit(t *testing.T) {
	t.Helper()
	v.MustCLI(t, "", "audit", "verify")
}

// Logs is everything valetd wrote to stdout.
func (v *Valet) Logs() string { return v.logs.String() }

// NtfySink records ntfy publishes.
type NtfySink struct {
	srv *httptest.Server
	mu  sync.Mutex
	got []Notification
}

// Notification is one ntfy publish.
type Notification struct {
	Title, Priority, Click, Body string
}

// NewNtfySink starts one.
func NewNtfySink(t *testing.T) *NtfySink {
	t.Helper()
	s := &NtfySink{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.got = append(s.got, Notification{r.Header.Get("Title"), r.Header.Get("Priority"), r.Header.Get("Click"), string(b)})
		s.mu.Unlock()
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// URL is the server's base URL.
func (s *NtfySink) URL() string { return s.srv.URL }

// Received returns the notifications so far.
func (s *NtfySink) Received() []Notification {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.got)
}

// WaitFor waits up to 5 s for a notification whose title contains substr.
func (s *NtfySink) WaitFor(t *testing.T, substr string) Notification {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, n := range s.Received() {
			if strings.Contains(n.Title, substr) {
				return n
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no alert containing %q; got %+v", substr, s.Received())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type bearer struct {
	token string
	next  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(r)
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
