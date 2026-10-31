package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xcwds/valet/internal/version"
)

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
		{"valetd prints version", []string{"valetd"}, ExitOK, "valetd v0.0.0-test\n", ""},
		{"valetd by path", []string{"/usr/local/bin/valetd"}, ExitOK, "valetd v0.0.0-test\n", ""},
		{"valetd.exe", []string{`C:\valet\valetd.exe`}, ExitOK, "valetd v0.0.0-test\n", ""},
		{"valet daemon", []string{"valet", "daemon"}, ExitOK, "valetd v0.0.0-test\n", ""},
		{"valetd version", []string{"valetd", "--version"}, ExitOK, "valetd v0.0.0-test\n", ""},
		{"valetd refuses to pretend", []string{"valetd", "--config", "valet.yaml"}, ExitUsage, "", "not supported yet"},
		{"name containing valetd is not valetd", []string{"notvaletd", "version"}, ExitOK, "valet v0.0.0-test\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(tt.args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, tt.wantCode, stderr.String())
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tt.wantStdout)
			}
			if tt.wantStdout == "" && stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
			if tt.wantStderr == "" && stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr.String())
			}
		})
	}
}
