package e2e

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeToken builds a GitHub-format token at run time, so no token-shaped
// string sits in the repository (CLAUDE.md: never commit one).
func fakeToken(prefix string) string { return prefix + strings.Repeat("Ab3", 12) }

func runNoCreds(t *testing.T, home, root string, env ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", filepath.Join("live", "no-creds.sh"))
	cmd.Env = append([]string{
		"HOME=" + home, "PATH=" + os.Getenv("PATH"), "NO_CREDS_ROOTS=" + root, "GIT_CONFIG_NOSYSTEM=1",
		"NO_CREDS_PROC=0",
	}, env...) // hermetic: not the host's other processes
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(out), ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), 0
}

func TestNoCredsScript(t *testing.T) {
	clean := func(t *testing.T) (home, root string) {
		home, root = t.TempDir(), t.TempDir()
		_ = os.MkdirAll(filepath.Join(home, ".valet"), 0o700)
		_ = os.WriteFile(filepath.Join(home, ".valet", "token"), []byte("vlt_sess_"+strings.Repeat("a", 52)), 0o600)
		_ = os.WriteFile(filepath.Join(root, "notes.txt"), []byte("nothing secret"), 0o600)
		return home, root
	}

	home, root := clean(t)
	if out, code := runNoCreds(t, home, root); code != 0 || !strings.Contains(out, "No GitHub credential found") || !strings.Contains(out, "Valet session token present") {
		t.Fatalf("clean container: exit %d\n%s", code, out)
	}

	cases := map[string]struct {
		setup func(home, root string) []string
		want  string
	}{
		"installation token in a file": {func(_, root string) []string {
			_ = os.WriteFile(filepath.Join(root, "leak.log"), []byte("token="+fakeToken("ghs_")), 0o600)
			return nil
		}, "in file"},
		"PAT in the environment": {func(string, string) []string { return []string{"SOME_VAR=" + fakeToken("ghp_")} }, "in this environment: SOME_VAR"},
		"GH_TOKEN set":           {func(string, string) []string { return []string{"GH_TOKEN=x"} }, "$GH_TOKEN is set"},
		"stored git credentials": {func(home, _ string) []string {
			_ = os.WriteFile(filepath.Join(home, ".git-credentials"), []byte("https://x:y@github.com"), 0o600)
			return nil
		}, "credential file"},
		"an auth header in git config": {func(home, _ string) []string {
			_ = os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[http \"https://github.com/\"]\n\textraHeader = AUTHORIZATION: basic eA==\n"), 0o600)
			return nil
		}, "in git config"},
		"fine-grained PAT in a file": {func(_, root string) []string {
			_ = os.WriteFile(filepath.Join(root, "x.env"), []byte("T=github_pat_"+strings.Repeat("Ab3_", 16)), 0o600)
			return nil
		}, "in file"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			home, root := clean(t)
			env := c.setup(home, root)
			out, code := runNoCreds(t, home, root, env...)
			if code != 1 || !strings.Contains(out, c.want) {
				t.Errorf("exit %d, want 1 and %q:\n%s", code, c.want, out)
			}
			if strings.Contains(out, fakeToken("ghs_")) || strings.Contains(out, fakeToken("ghp_")) {
				t.Error("the script printed a credential")
			}
		})
	}
}
