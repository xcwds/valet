package secrets

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewMasterKeyParses(t *testing.T) {
	enc, err := NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParseMasterKey(enc + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(k.ID()) != 16 {
		t.Errorf("ID = %q", k.ID())
	}
	enc2, _ := NewMasterKey()
	if enc == enc2 {
		t.Error("two generated keys are equal")
	}
}

func TestKeyIDIsStableAndDistinct(t *testing.T) {
	enc, _ := NewMasterKey()
	a, _ := ParseMasterKey(enc)
	b, _ := ParseMasterKey(enc)
	if a.ID() != b.ID() {
		t.Error("same key, different IDs")
	}
	other, _ := NewMasterKey()
	c, _ := ParseMasterKey(other)
	if a.ID() == c.ID() {
		t.Error("different keys, same ID")
	}
	raw, _ := base64.StdEncoding.DecodeString(enc)
	if strings.Contains(a.ID(), base64.StdEncoding.EncodeToString(raw[:6])) {
		t.Error("ID reveals key bytes")
	}
}

func TestParseMasterKeyErrors(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	tests := map[string]string{
		"empty":      "  \n",
		"not base64": "this-is-not-base64-but-is-secret!!",
		"too short":  short,
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseMasterKey(in)
			if err == nil {
				t.Fatal("accepted")
			}
			if strings.TrimSpace(in) != "" && strings.Contains(err.Error(), strings.TrimSpace(in)) {
				t.Errorf("error echoes the key material: %v", err)
			}
		})
	}
}

func TestLoadMasterKey(t *testing.T) {
	enc, _ := NewMasterKey()
	want, _ := ParseMasterKey(enc)
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	file := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(file, []byte(enc+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if k, err := LoadMasterKey(file, "", env(nil)); err != nil || k.ID() != want.ID() {
		t.Errorf("from file: %v", err)
	}
	if k, err := LoadMasterKey("", "MY_KEY", env(map[string]string{"MY_KEY": enc})); err != nil || k.ID() != want.ID() {
		t.Errorf("from named env: %v", err)
	}
	if k, err := LoadMasterKey("", "", env(map[string]string{DefaultKeyEnv: enc})); err != nil || k.ID() != want.ID() {
		t.Errorf("from default env: %v", err)
	}
	if _, err := LoadMasterKey("", "", env(nil)); err == nil || !strings.Contains(err.Error(), "init-key") {
		t.Errorf("missing key: %v", err)
	}
	if _, err := LoadMasterKey(filepath.Join(t.TempDir(), "nope"), "", env(nil)); err == nil {
		t.Error("missing file accepted")
	}
	// A file setting wins over the environment.
	if k, err := LoadMasterKey(file, "", env(map[string]string{DefaultKeyEnv: "garbage"})); err != nil || k.ID() != want.ID() {
		t.Errorf("file did not win: %v", err)
	}
}

func TestKeyEnvName(t *testing.T) {
	if got := KeyEnvName("/k", "X"); got != "" {
		t.Errorf("with a file: %q, want none", got)
	}
	if got := KeyEnvName("", "X"); got != "X" {
		t.Errorf("named: %q", got)
	}
	if got := KeyEnvName("", ""); got != DefaultKeyEnv {
		t.Errorf("default: %q", got)
	}
}
