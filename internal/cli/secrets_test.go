package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xcwds/valet/internal/secrets"
)

func TestInitKeyStdout(t *testing.T) {
	code, stdout, stderr := run(t, context.Background(), nil, "valet", "secrets", "init-key")
	if code != ExitOK {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
	if _, err := secrets.ParseMasterKey(stdout); err != nil {
		t.Fatalf("printed key doesn't parse: %v", err)
	}
}

func TestInitKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	code, stdout, stderr := run(t, context.Background(), nil, "valet", "secrets", "init-key", "--out", path)
	if code != ExitOK {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
	if stdout != "" {
		t.Errorf("key also printed to stdout: %q", stdout)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %#o, want 0600", info.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	if _, err := secrets.ParseMasterKey(string(b)); err != nil {
		t.Fatalf("written key doesn't parse: %v", err)
	}

	// Never overwrite an existing key.
	code, _, stderr = run(t, context.Background(), nil, "valet", "secrets", "init-key", "--out", path)
	if code != ExitError || !strings.Contains(stderr, "refusing to overwrite") {
		t.Fatalf("second init-key: code %d, stderr %q", code, stderr)
	}
	if b2, _ := os.ReadFile(path); string(b2) != string(b) {
		t.Fatal("existing key was changed")
	}
}

func TestSecretsSubcommandUsage(t *testing.T) {
	if code, _, _ := run(t, context.Background(), nil, "valet", "secrets"); code != ExitUsage {
		t.Errorf("bare secrets: code %d", code)
	}
	if code, _, _ := run(t, context.Background(), nil, "valet", "secrets", "nope"); code != ExitUsage {
		t.Errorf("unknown subcommand: code %d", code)
	}
	if code, _, _ := run(t, context.Background(), nil, "valet", "secrets", "set"); code != ExitUsage {
		t.Errorf("set without a name: code %d", code)
	}
	code, _, stderr := run(t, context.Background(), nil, "valet", "secrets", "list")
	if code != ExitError || !strings.Contains(stderr, "no admin token") {
		t.Errorf("list without a token: code %d, stderr %q", code, stderr)
	}
}
