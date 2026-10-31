package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyCheck(t *testing.T) {
	code, out, errOut := run(t, context.Background(), nil, "valet", "policy", "check",
		"--role", "reviewer", "--action", "github.pr.review.submit", "--repo", "xcwds/site",
		"--params", `{"repo":"xcwds/site","number":7,"event":"APPROVE"}`)
	if code != ExitOK || !strings.HasPrefix(out, "DENY (alert)") || !strings.Contains(out, "reviewer/never-approve") {
		t.Fatalf("code %d, out %q, err %q", code, out, errOut)
	}
	code, out, _ = run(t, context.Background(), nil, "valet", "policy", "check",
		"--role", "implementer", "--action", "git.push", "--repo", "xcwds/site", "--job", "job-k3x9q2ma",
		"--params", `{"repo":"xcwds/site","refs":[{"name":"refs/heads/agent/job-k3x9q2ma/fix","delete":false}]}`)
	if code != ExitOK || !strings.HasPrefix(out, "ALLOW") {
		t.Fatalf("push: code %d, out %q", code, out)
	}
}

func TestPolicyCheckCustomFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roles.yaml")
	if err := os.WriteFile(path, []byte("role: bot\nrules:\n  - action: fake.echo\n    decision: allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, context.Background(), map[string]string{"VALET_POLICIES": path}, "valet", "policy", "check", "--role", "bot", "--action", "fake.echo")
	if code != ExitOK || !strings.HasPrefix(out, "ALLOW") {
		t.Fatalf("code %d, out %q", code, out)
	}
	if err := os.WriteFile(path, []byte("role: bot\nrules:\n  - action: fake.echo\n    when: params.x ==\n    decision: allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := run(t, context.Background(), nil, "valet", "policy", "check", "--policies", path, "--role", "bot", "--action", "fake.echo")
	if code != ExitError || !strings.Contains(errOut, "bot#1") {
		t.Fatalf("broken policy: code %d, err %q", code, errOut)
	}
}

func TestValetdRefusesABrokenPolicy(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "roles.yaml")
	if err := os.WriteFile(bad, []byte("role: r\nrules:\n  - action: x.a\n    when: job.repoz\n    decision: allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeFile(t, loopbackConfig(t)+"policies: "+bad+"\n")
	code, stderr := runUntilStarted(t, path, map[string]string{"VALET_MASTER_KEY": testKey})
	if code != ExitError || !strings.Contains(stderr, "repoz") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
}

func TestJobCreateRefusesUndefinedRoles(t *testing.T) {
	v := startValetd(t)
	code, _, errOut := v.cli(t, "", "job", "create", "--role", "root")
	if code != ExitError || !strings.Contains(errOut, "not defined in the policy") {
		t.Fatalf("code %d, err %q", code, errOut)
	}
}

func TestValetdRefusesABadConnectorsFile(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "connectors.yaml")
	if err := os.WriteFile(bad, []byte("github:\n  app_id: '1'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeFile(t, loopbackConfig(t)+"connectors: "+bad+"\n")
	code, stderr := runUntilStarted(t, path, map[string]string{"VALET_MASTER_KEY": testKey})
	if code != ExitError || !strings.Contains(stderr, "installation_id is required") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
}
