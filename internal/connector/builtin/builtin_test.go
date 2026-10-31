package builtin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "connectors.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad(t *testing.T) {
	if cs, err := Load("", Deps{}); err != nil || len(cs) != 0 {
		t.Fatalf("no file: %v %v", cs, err)
	}
	cs, err := Load(write(t, "github:\n  app_id: '123'\n  installation_id: 42\n  private_key_secret: github/app-key\n"), Deps{})
	if err != nil || len(cs) != 1 || cs[0].Name() != "github" {
		t.Fatalf("github: %v %v", cs, err)
	}
	if cs, err := Load(write(t, ""), Deps{}); err != nil || len(cs) != 0 {
		t.Fatalf("empty file: %v %v", cs, err)
	}
}

func TestLoadErrors(t *testing.T) {
	for name, body := range map[string]string{
		"unknown connector": "gitlab:\n  url: x\n",
		"unknown key":       "github:\n  app_id: '1'\n  installation_id: 2\n  private_key_secret: k\n  private_key: inline\n",
		"invalid config":    "github:\n  app_id: '1'\n",
	} {
		if _, err := Load(write(t, body), Deps{}); err == nil {
			t.Errorf("%s: loaded", name)
		} else if strings.Contains(err.Error(), "inline") {
			t.Errorf("%s: error echoes a value: %v", name, err)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml"), Deps{}); err == nil {
		t.Error("missing file loaded")
	}
}
