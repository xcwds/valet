package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

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

func writeFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "valet.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const loopbackConfig = `
data_dir: /unused
listen:
  admin: 127.0.0.1:0
  agent: 127.0.0.1:0
  egress: 127.0.0.1:0
`

func TestValetdStartsAndStopsOnSignal(t *testing.T) {
	path := writeFile(t, loopbackConfig)
	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- Run(ctx, []string{"valetd", "--config", path}, IO{Stdout: &stdout, Stderr: &stderr, Getenv: func(string) string { return "" }})
	}()

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(stdout.String(), `"msg":"started"`) {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("valetd did not start; stdout %q, stderr %q", stdout.String(), stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel() // what SIGINT/SIGTERM do in main
	select {
	case code := <-done:
		if code != ExitOK {
			t.Fatalf("exit code = %d, stderr %q", code, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("valetd did not stop")
	}
	if !strings.Contains(stdout.String(), `"msg":"stopped"`) {
		t.Errorf("no stop log: %q", stdout.String())
	}
}

func TestValetdConfigFromEnv(t *testing.T) {
	path := writeFile(t, "data_dir: /d\nbogus: 1\n")
	code, _, stderr := run(t, context.Background(), map[string]string{"VALET_CONFIG": path}, "valetd")
	if code != ExitError || !strings.Contains(stderr, "bogus") {
		t.Fatalf("code %d, stderr %q; want the unknown key reported", code, stderr)
	}
}

func TestValetdRejectsBadConfig(t *testing.T) {
	path := writeFile(t, "data_dir: /d\nlisten:\n  admn: ':1'\n")
	code, stdout, stderr := run(t, context.Background(), nil, "valetd", "--config", path)
	if code != ExitError {
		t.Errorf("exit code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr, "admn") {
		t.Errorf("stderr = %q, want it to name the unknown key", stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing (nothing started)", stdout)
	}
}

func TestValetdNeedsDataDir(t *testing.T) {
	code, _, stderr := run(t, context.Background(), nil, "valetd")
	if code != ExitError || !strings.Contains(stderr, "data_dir is required") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
}

func TestValetdFlags(t *testing.T) {
	if code, _, stderr := run(t, context.Background(), nil, "valetd", "--nope"); code != ExitUsage || !strings.Contains(stderr, "--nope") && !strings.Contains(stderr, "-nope") {
		t.Errorf("unknown flag: code %d, stderr %q", code, stderr)
	}
	if code, _, _ := run(t, context.Background(), nil, "valetd", "extra"); code != ExitUsage {
		t.Errorf("stray argument: code %d, want %d", code, ExitUsage)
	}
	code, _, stderr := run(t, context.Background(), nil, "valetd", "-h")
	if code != ExitOK || !strings.Contains(stderr, "VALET_DATA_DIR") {
		t.Errorf("-h: code %d, stderr %q; want usage listing env overrides", code, stderr)
	}
}
