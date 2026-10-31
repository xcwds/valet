package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xcwds/valet/internal/store"
)

// startedDataDir runs valetd once (start and stop) so its data dir holds a
// real audit log, and returns the config path and data dir.
func startedDataDir(t *testing.T) (string, string) {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "data")
	path := writeFile(t, "data_dir: "+dataDir+"\nlisten: {admin: '127.0.0.1:0', agent: '127.0.0.1:0', egress: '127.0.0.1:0'}\n")
	env := map[string]string{"VALET_MASTER_KEY": testKey}
	if code, stderr := runUntilStarted(t, path, env); code != ExitOK {
		t.Fatalf("valetd: %d %q", code, stderr)
	}
	return path, dataDir
}

func TestAuditTailShowsTheLifecycle(t *testing.T) {
	_, dataDir := startedDataDir(t)
	code, stdout, stderr := run(t, context.Background(), nil, "valet", "audit", "tail", "--data-dir", dataDir)
	if code != ExitOK {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
	var actions []string
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		var r struct{ Action, Decision string }
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("not JSON: %q", line)
		}
		actions = append(actions, r.Action)
	}
	if got := strings.Join(actions, ","); got != "master_key.record,admin_token.create,valetd.start,valetd.stop" {
		t.Errorf("actions = %s", got)
	}
}

func TestAuditTailFiltersAndEnv(t *testing.T) {
	_, dataDir := startedDataDir(t)
	code, stdout, _ := run(t, context.Background(), map[string]string{"VALET_DATA_DIR": dataDir}, "valet", "audit", "tail", "-n", "1")
	if code != ExitOK || strings.Count(stdout, "\n") != 1 || !strings.Contains(stdout, "valetd.stop") {
		t.Fatalf("code %d, stdout %q", code, stdout)
	}
	code, stdout, _ = run(t, context.Background(), nil, "valet", "audit", "tail", "--data-dir", dataDir, "--decision", "deny")
	if code != ExitOK || stdout != "" {
		t.Fatalf("no denies expected: code %d, stdout %q", code, stdout)
	}
}

func TestAuditVerify(t *testing.T) {
	_, dataDir := startedDataDir(t)
	code, stdout, stderr := run(t, context.Background(), nil, "valet", "audit", "verify", "--data-dir", dataDir)
	if code != ExitOK || !strings.Contains(stdout, "ok: 4 events") {
		t.Fatalf("code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

// breakChain edits an audit row behind valetd's back.
func breakChain(t *testing.T, dataDir string) {
	t.Helper()
	st, err := store.Open(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Write(context.Background(), func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DROP TRIGGER audit_events_no_update`); err != nil {
			return err
		}
		_, err := tx.Exec(`UPDATE audit_events SET decision = 'deny' WHERE seq = 2`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAuditVerifyReportsABreak(t *testing.T) {
	_, dataDir := startedDataDir(t)
	breakChain(t, dataDir)
	code, stdout, _ := run(t, context.Background(), nil, "valet", "audit", "verify", "--data-dir", dataDir)
	if code != ExitError || !strings.Contains(stdout, "BROKEN at seq 2") {
		t.Fatalf("code %d, stdout %q", code, stdout)
	}
}

func TestValetdRefusesABrokenChain(t *testing.T) {
	path, dataDir := startedDataDir(t)
	breakChain(t, dataDir)
	code, stderr := runUntilStarted(t, path, map[string]string{"VALET_MASTER_KEY": testKey})
	if code != ExitError || !strings.Contains(stderr, "audit log is broken at seq 2") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
}

func TestAuditNeedsADataDir(t *testing.T) {
	for _, sub := range []string{"tail", "verify"} {
		code, _, stderr := run(t, context.Background(), nil, "valet", "audit", sub)
		if code != ExitUsage || !strings.Contains(stderr, "data-dir") {
			t.Errorf("%s: code %d, stderr %q", sub, code, stderr)
		}
	}
	code, _, _ := run(t, context.Background(), nil, "valet", "audit", "verify", "--data-dir", filepath.Join(t.TempDir(), "none"))
	if code != ExitError {
		t.Errorf("missing data dir: code %d", code)
	}
}
