package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/xcwds/valet/internal/version"
)

// run calls Run with buffers and the given environment.
func run(t *testing.T, ctx context.Context, env map[string]string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(ctx, args, IO{Stdout: &out, Stderr: &errOut, Getenv: func(k string) string { return env[k] }})
	return code, out.String(), errOut.String()
}

func TestRun(t *testing.T) {
	old := version.Version
	t.Cleanup(func() { version.Version = old })
	version.Version = "v0.0.0-test"

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{"valet version", []string{"valet", "version"}, ExitOK, "valet v0.0.0-test\n", ""},
		{"valet --version", []string{"/usr/local/bin/valet", "--version"}, ExitOK, "valet v0.0.0-test\n", ""},
		{"version with extra args", []string{"valet", "version", "x"}, ExitUsage, "", "unexpected arguments"},
		{"no command", []string{"valet"}, ExitUsage, "", "Usage: valet"},
		{"no args at all", nil, ExitUsage, "", "Usage: valet"},
		{"unknown command", []string{"valet", "frobnicate"}, ExitUsage, "", `unknown command "frobnicate"`},
		{"help", []string{"valet", "help"}, ExitOK, "Usage: valet", ""},
		{"valetd version", []string{"valetd", "version"}, ExitOK, "valetd v0.0.0-test\n", ""},
		{"valetd --version by path", []string{"/usr/local/bin/valetd", "--version"}, ExitOK, "valetd v0.0.0-test\n", ""},
		{"valetd.exe version", []string{`C:\valet\valetd.exe`, "version"}, ExitOK, "valetd v0.0.0-test\n", ""},
		{"valet daemon version", []string{"valet", "daemon", "version"}, ExitOK, "valetd v0.0.0-test\n", ""},
		{"name containing valetd is not valetd", []string{"notvaletd", "version"}, ExitOK, "valet v0.0.0-test\n", ""},
		{"job create needs a role", []string{"valet", "job", "create"}, ExitUsage, "", "--role is required"},
		{"session login needs a code", []string{"valet", "session", "login", "--code-file", "/nonexistent/code"}, ExitError, "", "reading the enrollment code"},
		{"approve not yet", []string{"valet", "approve", "x"}, ExitError, "", "not implemented yet (#23)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(t, context.Background(), nil, tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, tt.wantCode, stderr)
			}
			if !strings.Contains(stdout, tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout, tt.wantStdout)
			}
			if tt.wantStdout == "" && stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.wantStderr)
			}
			if tt.wantStderr == "" && stderr != "" {
				t.Errorf("stderr = %q, want empty", stderr)
			}
		})
	}
}

func TestEveryPlannedCommandIsDispatched(t *testing.T) {
	for cmd, issue := range plannedIn {
		code, _, stderr := run(t, context.Background(), nil, "valet", cmd)
		if code != ExitError || !strings.Contains(stderr, issue) {
			t.Errorf("valet %s: code %d, stderr %q; want ExitError naming %s", cmd, code, stderr, issue)
		}
	}
}
