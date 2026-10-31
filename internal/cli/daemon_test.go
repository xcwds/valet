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

	"github.com/xcwds/valet/internal/secrets"
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

// testKey is a master key generated per test binary run.
var testKey = func() string {
	k, err := secrets.NewMasterKey()
	if err != nil {
		panic(err)
	}
	return k
}()

// keyEnv supplies the master key the way an operator would, through
// $VALET_MASTER_KEY.
func keyEnv(k string) string {
	if k == secrets.DefaultKeyEnv {
		return testKey
	}
	return ""
}

func writeFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "valet.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func loopbackConfig(t *testing.T) string {
	t.Helper()
	return "data_dir: " + filepath.Join(t.TempDir(), "data") + `
listen:
  admin: 127.0.0.1:0
  agent: 127.0.0.1:0
  egress: 127.0.0.1:0
`
}

func TestValetdStartsAndStopsOnSignal(t *testing.T) {
	path := writeFile(t, loopbackConfig(t))
	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- Run(ctx, []string{"valetd", "--config", path}, IO{Stdout: &stdout, Stderr: &stderr, Getenv: keyEnv})
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

func TestValetdCreatesTheDatabase(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	path := writeFile(t, "data_dir: "+dataDir+"\nlisten: {admin: '127.0.0.1:0', agent: '127.0.0.1:0', egress: '127.0.0.1:0'}\n")
	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- Run(ctx, []string{"valetd", "--config", path}, IO{Stdout: &stdout, Stderr: &stderr, Getenv: keyEnv})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(stdout.String(), `"msg":"started"`) {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("valetd did not start; stderr %q", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if code := <-done; code != ExitOK {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dataDir, "valet.db")); err != nil {
		t.Fatalf("database not created: %v", err)
	}
}

func TestValetdRefusesAnUnusableDataDir(t *testing.T) {
	notADir := writeFile(t, "") // a file where the data directory should be
	path := writeFile(t, "data_dir: "+notADir+"\nlisten: {admin: '127.0.0.1:0', agent: '127.0.0.1:0', egress: '127.0.0.1:0'}\n")
	code, stdout, stderr := run(t, context.Background(), map[string]string{secrets.DefaultKeyEnv: testKey}, "valetd", "--config", path)
	if code != ExitError || !strings.Contains(stderr, "store:") {
		t.Fatalf("code %d, stderr %q; want a store error", code, stderr)
	}
	if strings.Contains(stdout, "started") {
		t.Errorf("listeners started before the database opened: %q", stdout)
	}
}

func TestValetdNeedsAMasterKey(t *testing.T) {
	path := writeFile(t, loopbackConfig(t))
	code, stdout, stderr := run(t, context.Background(), nil, "valetd", "--config", path)
	if code != ExitError || !strings.Contains(stderr, "no master key") || !strings.Contains(stderr, "init-key") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
	if stdout != "" {
		t.Errorf("started without a key: %q", stdout)
	}
}

// runUntilStarted starts valetd with env and stops it once it has started,
// returning the exit code and stderr.
func runUntilStarted(t *testing.T, path string, env map[string]string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- Run(ctx, []string{"valetd", "--config", path}, IO{Stdout: &stdout, Stderr: &stderr, Getenv: func(k string) string { return env[k] }})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case code := <-done:
			return code, stderr.String()
		default:
		}
		if strings.Contains(stdout.String(), `"msg":"started"`) {
			cancel()
			return <-done, stderr.String()
		}
		if time.Now().After(deadline) {
			t.Fatalf("valetd neither started nor exited; stderr %q", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestValetdRefusesADifferentKeyOnRestart(t *testing.T) {
	path := writeFile(t, loopbackConfig(t))
	if code, stderr := runUntilStarted(t, path, map[string]string{secrets.DefaultKeyEnv: testKey}); code != ExitOK {
		t.Fatalf("first start: %d %q", code, stderr)
	}
	other, _ := secrets.NewMasterKey()
	code, stderr := runUntilStarted(t, path, map[string]string{secrets.DefaultKeyEnv: other})
	if code != ExitError || !strings.Contains(stderr, "does not match this database") {
		t.Fatalf("code %d, stderr %q; want the other key refused", code, stderr)
	}
	if code, stderr := runUntilStarted(t, path, map[string]string{secrets.DefaultKeyEnv: testKey}); code != ExitOK {
		t.Fatalf("restart with the right key: %d %q", code, stderr)
	}
}

func TestValetdKeyFromFile(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "master.key")
	if code, _, stderr := run(t, context.Background(), nil, "valet", "secrets", "init-key", "--out", keyFile); code != ExitOK {
		t.Fatalf("init-key: %q", stderr)
	}
	path := writeFile(t, loopbackConfig(t)+"master_key: {file: "+keyFile+"}\n")
	if code, stderr := runUntilStarted(t, path, nil); code != ExitOK {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
}

func TestValetdUnsetsTheKeyVariable(t *testing.T) {
	path := writeFile(t, loopbackConfig(t))
	env := map[string]string{secrets.DefaultKeyEnv: testKey}
	var unset []string
	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- Run(ctx, []string{"valetd", "--config", path}, IO{
			Stdout: &stdout, Stderr: &stderr,
			Getenv:   func(k string) string { return env[k] },
			Unsetenv: func(k string) error { unset = append(unset, k); return nil },
		})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(stdout.String(), `"msg":"started"`) {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("did not start: %q", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if len(unset) != 1 || unset[0] != secrets.DefaultKeyEnv {
		t.Fatalf("unset = %v, want [%s]", unset, secrets.DefaultKeyEnv)
	}
}
