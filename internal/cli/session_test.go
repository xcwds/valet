package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func init() { loginBackoff = 10 * time.Millisecond }

// enrollCode creates a job with --enroll and writes its code to a file, as
// a launcher would hand it to the container.
func enrollCode(t *testing.T, v *liveValetd, role string) (jobID, codeFile string) {
	t.Helper()
	code, out, errOut := v.cli(t, "", "job", "create", "--role", role, "--repo", "xcwds/site", "--enroll", "--json")
	if code != ExitOK {
		t.Fatalf("job create --enroll: %d %s", code, errOut)
	}
	var created struct {
		Job        struct{ ID string }
		Token      string
		Enrollment struct{ Code string }
	}
	if err := json.Unmarshal([]byte(out), &created); err != nil || created.Token != "" || !strings.HasPrefix(created.Enrollment.Code, "vlt_enroll_") {
		t.Fatalf("output %s (%v)", out, err)
	}
	codeFile = filepath.Join(t.TempDir(), "valet_enroll")
	if err := os.WriteFile(codeFile, []byte(created.Enrollment.Code+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return created.Job.ID, codeFile
}

func login(t *testing.T, agentURL, codeFile, tokenFile string, extra ...string) (int, string) {
	t.Helper()
	var out, errOut syncBuffer
	code := Run(t.Context(), append([]string{"valet", "session", "login", "--url", agentURL, "--code-file", codeFile, "--token-file", tokenFile}, extra...),
		IO{Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }})
	return code, errOut.String()
}

func TestSessionLogin(t *testing.T) {
	v := startValetd(t)
	jobID, codeFile := enrollCode(t, v, "reviewer")
	tokenFile := filepath.Join(t.TempDir(), "home", ".valet", "token")
	if code, errOut := login(t, v.agent, codeFile, tokenFile); code != ExitOK || !strings.Contains(errOut, jobID) {
		t.Fatalf("login: %d %s", code, errOut)
	}
	st, err := os.Stat(tokenFile)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("token file: %v %v", st, err)
	}
	if _, err := os.Stat(codeFile); !os.IsNotExist(err) {
		t.Error("the code file was not deleted")
	}
	tok, _ := os.ReadFile(tokenFile)
	if s := status(t, "GET", v.agent+"/mcp", "Bearer "+strings.TrimSpace(string(tok))); s != http.StatusMethodNotAllowed {
		t.Errorf("the session token doesn't authenticate: %d", s)
	}
	_, out, _ := v.cli(t, "", "audit", "tail", "--job", jobID)
	if !strings.Contains(out, `"action":"session.enroll"`) || !strings.Contains(out, `"interface":"enroll"`) {
		t.Errorf("enrollment not audited: %s", out)
	}
	if strings.Contains(out, strings.TrimSpace(string(tok))) {
		t.Error("the session token is in the audit log")
	}
}

// The response to the first use is lost; the CLI retries with the same code
// and gets the same token back, as a replay.
func TestSessionLoginRetriesALostResponse(t *testing.T) {
	v := startValetd(t)
	jobID, codeFile := enrollCode(t, v, "implementer")
	target, _ := url.Parse(v.agent)
	var calls atomic.Int32
	var firstBody []byte
	lossy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		resp, err := http.Post(target.String()+r.URL.Path, "application/json", bytes.NewReader(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if calls.Add(1) == 1 {
			firstBody = b
			// Valet answered; the answer never reaches the container.
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
			return
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(b)
	}))
	t.Cleanup(lossy.Close)

	tokenFile := filepath.Join(t.TempDir(), "token")
	if code, errOut := login(t, lossy.URL, codeFile, tokenFile); code != ExitOK {
		t.Fatalf("login: %d %s", code, errOut)
	}
	if calls.Load() != 2 {
		t.Errorf("%d attempts, want 2", calls.Load())
	}
	var first struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(firstBody, &first)
	tok, _ := os.ReadFile(tokenFile)
	if first.SessionToken == "" || strings.TrimSpace(string(tok)) != first.SessionToken {
		t.Error("the retry didn't get the first answer's token")
	}
	_, out, _ := v.cli(t, "", "audit", "tail", "--job", jobID)
	if !strings.Contains(out, `"replay":true`) || strings.Contains(out, `"decision":"deny"`) {
		t.Errorf("audit: %s", out)
	}
}

func TestSessionLoginRefused(t *testing.T) {
	v := startValetd(t)
	jobID, codeFile := enrollCode(t, v, "reviewer")
	v.cli(t, "", "job", "revoke", jobID)
	tokenFile := filepath.Join(t.TempDir(), "token")
	code, errOut := login(t, v.agent, codeFile, tokenFile)
	if code == ExitOK || !strings.Contains(errOut, "enrollment refused") {
		t.Fatalf("login for a revoked job: %d %s", code, errOut)
	}
	if _, err := os.Stat(codeFile); !os.IsNotExist(err) {
		t.Error("a refused code was kept")
	}
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Error("a token file was written")
	}
}

func TestSessionLoginKeepsTheCodeWhenValetIsUnreachable(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	codeFile := filepath.Join(t.TempDir(), "code")
	_ = os.WriteFile(codeFile, []byte("vlt_enroll_"+strings.Repeat("a", 52)), 0o600)
	code, errOut := login(t, deadURL, codeFile, filepath.Join(t.TempDir(), "token"), "--timeout", "200ms")
	if code == ExitOK || !strings.Contains(errOut, "gave up") {
		t.Fatalf("%d %s", code, errOut)
	}
	if _, err := os.Stat(codeFile); err != nil {
		t.Error("the code was deleted though Valet never answered")
	}
}

// The agent port has no route that creates jobs or sessions other than
// /enroll; jobs are made on the admin port only.
func TestNoJobCreationOnTheAgentPort(t *testing.T) {
	v := startValetd(t)
	_, out, _ := v.cli(t, "", "job", "create", "--role", "implementer", "--repo", "xcwds/site", "--json")
	var created struct{ Token string }
	_ = json.Unmarshal([]byte(out), &created)
	for _, path := range []string{"/api/jobs", "/jobs", "/enroll/new", "/api/jobs/x/enroll", "/session"} {
		req, _ := http.NewRequestWithContext(t.Context(), "POST", v.agent+path, strings.NewReader(`{"role":"implementer"}`))
		req.Header.Set("Authorization", "Bearer "+created.Token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s on the agent port: %d, want 404", path, resp.StatusCode)
		}
	}
}

// If the token can't be saved, the code stays for a retry.
func TestSessionLoginKeepsTheCodeIfTheTokenCantBeSaved(t *testing.T) {
	v := startValetd(t)
	_, codeFile := enrollCode(t, v, "reviewer")
	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	_ = os.WriteFile(blocked, nil, 0o600)
	code, errOut := login(t, v.agent, codeFile, filepath.Join(blocked, "token"))
	if code == ExitOK || !strings.Contains(errOut, "writing the session token") {
		t.Fatalf("%d %s", code, errOut)
	}
	if _, err := os.Stat(codeFile); err != nil {
		t.Fatal("the code was deleted though the token was never saved")
	}
	// A retry within the window gets the same session.
	if code, errOut := login(t, v.agent, codeFile, filepath.Join(t.TempDir(), "token")); code != ExitOK {
		t.Fatalf("retry: %d %s", code, errOut)
	}
}
