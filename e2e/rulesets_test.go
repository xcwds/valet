package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeGH is a stand-in for `gh api` that serves canned responses from a
// directory (one file per path, slashes and ? as _) and logs every call.
const fakeGH = `#!/usr/bin/env bash
set -euo pipefail
shift # "api"
method=GET jq_expr="" path=""
while [ $# -gt 0 ]; do
	case $1 in
	-X) method=$2; shift 2 ;;
	--jq) jq_expr=$2; shift 2 ;;
	--input) shift 2 ;;
	*) path=$1; shift ;;
	esac
done
echo "$method $path" >>"$FAKE_DIR/calls"
[ "$method" = GET ] || { echo '{}'; exit 0; }
f="$FAKE_DIR/$(tr '/?' '__' <<<"$path")"
[ -f "$f" ] || { echo "gh: Not Found (HTTP 404)" >&2; exit 1; }
if [ -n "$jq_expr" ]; then jq -r "$jq_expr" "$f"; else cat "$f"; fi
`

type fakeRepo map[string]any // API path -> response

func runScript(t *testing.T, script string, repo fakeRepo, args ...string) (string, []string, int) {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed")
	}
	dir := t.TempDir()
	gh := filepath.Join(dir, "gh")
	if err := os.WriteFile(gh, []byte(fakeGH), 0o700); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(dir, "data")
	_ = os.Mkdir(data, 0o700)
	for path, v := range repo {
		b, _ := json.Marshal(v)
		name := strings.NewReplacer("/", "_", "?", "_").Replace(path)
		if err := os.WriteFile(filepath.Join(data, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", append([]string{filepath.Join("..", "deploy", "github", script)}, args...)...)
	cmd.Env = append(os.Environ(), "GH="+gh, "FAKE_DIR="+data)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	calls, _ := os.ReadFile(filepath.Join(data, "calls"))
	return string(out), strings.Split(strings.TrimSpace(string(calls)), "\n"), code
}

func loadRuleset(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "deploy", "github", name))
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return v
}

// rulesOf turns a ruleset file into what GET rules/branches returns.
func rulesOf(rs ...map[string]any) []any {
	var out []any
	for _, r := range rs {
		out = append(out, r["rules"].([]any)...)
	}
	return out
}

// wellProtected is a repository with deploy/github's rulesets applied.
func wellProtected(t *testing.T) fakeRepo {
	protected := loadRuleset(t, "protected-branches.json")
	agent := loadRuleset(t, "agent-branches.json")
	tags := loadRuleset(t, "tags.json")
	for i, r := range []map[string]any{protected, agent, tags} {
		r["id"] = i + 1
	}
	return fakeRepo{
		"repos/xcwds/site":                                  map[string]any{"default_branch": "main"},
		"repos/xcwds/site/rules/branches/main":              rulesOf(protected),
		"repos/xcwds/site/rules/branches/agent/valet-check": rulesOf(agent),
		"repos/xcwds/site/contents/.github/CODEOWNERS":      map[string]any{"path": ".github/CODEOWNERS"},
		"repos/xcwds/site/rulesets?includes_parents=true":   []any{protected, agent, tags},
		"repos/xcwds/site/rulesets/1":                       protected,
		"repos/xcwds/site/rulesets/2":                       agent,
		"repos/xcwds/site/rulesets/3":                       tags,
	}
}

func TestRulesetFilesMatchTheRFC(t *testing.T) {
	protected := loadRuleset(t, "protected-branches.json")
	if bp := protected["bypass_actors"].([]any); len(bp) != 0 {
		t.Errorf("protected branches have bypass actors: %v", bp)
	}
	inc := protected["conditions"].(map[string]any)["ref_name"].(map[string]any)["include"].([]any)
	if !strings.Contains(jsonString(inc), "refs/heads/release/**") || !strings.Contains(jsonString(inc), "~DEFAULT_BRANCH") {
		t.Errorf("release/** not protected: %v", inc)
	}
	for _, f := range []string{"agent-branches.json", "tags.json"} {
		for _, a := range loadRuleset(t, f)["bypass_actors"].([]any) {
			if a.(map[string]any)["actor_type"] != "RepositoryRole" {
				t.Errorf("%s: bypass by %v; only repository admins may bypass", f, a)
			}
		}
	}
}

func jsonString(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestCheckPassesAProtectedRepo(t *testing.T) {
	out, _, code := runScript(t, "check.sh", wellProtected(t), "xcwds/site", "--app-id", "12345")
	if code != 0 || strings.Contains(out, "FAIL") || strings.Contains(out, "WARN") || !strings.Contains(out, "The second wall is up") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestCheckFindsGaps(t *testing.T) {
	cases := map[string]struct {
		mutate func(fakeRepo)
		args   []string
		want   string
	}{
		"no code owner review": {func(r fakeRepo) {
			rules := r["repos/xcwds/site/rules/branches/main"].([]any)
			for _, x := range rules {
				if m := x.(map[string]any); m["type"] == "pull_request" {
					m["parameters"].(map[string]any)["require_code_owner_review"] = false
				}
			}
		}, nil, "FAIL  main: no rule requiring a pull request approved by a code owner"},
		"main unprotected": {func(r fakeRepo) { r["repos/xcwds/site/rules/branches/main"] = []any{} }, nil, "FAIL  main: force push allowed"},
		"agent branches deletable": {func(r fakeRepo) {
			r["repos/xcwds/site/rules/branches/agent/valet-check"] = []any{map[string]any{"type": "non_fast_forward"}}
		}, nil, "FAIL  agent/**: deletion allowed"},
		"no CODEOWNERS": {func(r fakeRepo) { delete(r, "repos/xcwds/site/contents/.github/CODEOWNERS") }, nil, "FAIL  no CODEOWNERS file"},
		"the App can bypass": {func(r fakeRepo) {
			rs := r["repos/xcwds/site/rulesets/1"].(map[string]any)
			rs["bypass_actors"] = []any{map[string]any{"actor_id": 12345, "actor_type": "Integration", "bypass_mode": "always"}}
		}, []string{"--app-id", "12345"}, `FAIL  ruleset "valet: protected branches": Valet's App (12345) can bypass it`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			repo := wellProtected(t)
			c.mutate(repo)
			out, _, code := runScript(t, "check.sh", repo, append([]string{"xcwds/site"}, c.args...)...)
			if code != 1 || !strings.Contains(out, c.want) {
				t.Errorf("exit %d, want 1 and %q:\n%s", code, c.want, out)
			}
		})
	}
	// Without --app-id, any App on a bypass list is a warning.
	repo := wellProtected(t)
	repo["repos/xcwds/site/rulesets/2"].(map[string]any)["bypass_actors"] = []any{map[string]any{"actor_id": 9, "actor_type": "Integration"}}
	if out, _, _ := runScript(t, "check.sh", repo, "xcwds/site"); !strings.Contains(out, `WARN  ruleset "valet: agent branches": a GitHub App can bypass it`) {
		t.Errorf("no warning for an App bypass:\n%s", out)
	}
}

func TestApplyCreatesThenUpdates(t *testing.T) {
	_, calls, code := runScript(t, "apply.sh", fakeRepo{"repos/xcwds/site/rulesets": []any{}}, "xcwds/site")
	if code != 0 || strings.Count(strings.Join(calls, "\n"), "POST repos/xcwds/site/rulesets") != 3 {
		t.Fatalf("create: exit %d, calls %v", code, calls)
	}
	existing := []any{
		map[string]any{"id": 7, "name": "valet: protected branches"},
		map[string]any{"id": 8, "name": "valet: agent branches"},
	}
	_, calls, code = runScript(t, "apply.sh", fakeRepo{"repos/xcwds/site/rulesets": existing}, "xcwds/site")
	joined := strings.Join(calls, "\n")
	if code != 0 || !strings.Contains(joined, "PUT repos/xcwds/site/rulesets/7") || !strings.Contains(joined, "PUT repos/xcwds/site/rulesets/8") ||
		!strings.Contains(joined, "POST repos/xcwds/site/rulesets") {
		t.Fatalf("update: exit %d, calls %v", code, calls)
	}
}
