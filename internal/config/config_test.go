package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "valet.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadFile(t *testing.T) {
	path := writeConfig(t, `
data_dir: /var/lib/valet
listen:
  admin: 10.0.0.2:14400
  agent: 172.20.0.2:14401
master_key:
  file: /run/secrets/master_key
log:
  level: debug
  format: text
policies: /etc/valet/policies
connectors: /etc/valet/connectors
`)
	cfg, err := Load(path, envFrom(nil))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		DataDir:    "/var/lib/valet",
		Listen:     Listen{Admin: "10.0.0.2:14400", Agent: "172.20.0.2:14401", Egress: DefaultEgressAddr},
		MasterKey:  MasterKey{File: "/run/secrets/master_key"},
		Log:        Log{Level: "debug", Format: "text"},
		Policies:   "/etc/valet/policies",
		Connectors: "/etc/valet/connectors",
		Egress:     Egress{Ports: []int{443}},
	}
	if !reflect.DeepEqual(*cfg, want) {
		t.Fatalf("got %+v\nwant %+v", *cfg, want)
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := Load("", envFrom(map[string]string{"VALET_DATA_DIR": "/data"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen.Admin != "127.0.0.1:14400" || cfg.Listen.Agent != ":14401" || cfg.Listen.Egress != ":14402" {
		t.Errorf("listen defaults = %+v", cfg.Listen)
	}
	if cfg.Log.Level != "info" || cfg.Log.Format != "json" {
		t.Errorf("log defaults = %+v", cfg.Log)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	path := writeConfig(t, "data_dir: /from/file\nlog: {level: info}\n")
	cfg, err := Load(path, envFrom(map[string]string{
		"VALET_DATA_DIR":    "/from/env",
		"VALET_LOG_LEVEL":   "warn",
		"VALET_ADMIN_ADDR":  "0.0.0.0:9000",
		"VALET_AGENT_ADDR":  ":9001",
		"VALET_EGRESS_ADDR": ":9002",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != "/from/env" || cfg.Log.Level != "warn" || cfg.Listen.Admin != "0.0.0.0:9000" ||
		cfg.Listen.Agent != ":9001" || cfg.Listen.Egress != ":9002" {
		t.Fatalf("env did not override: %+v", cfg)
	}
}

func TestEveryEnvNameIsApplied(t *testing.T) {
	for _, name := range EnvNames() {
		var after Config
		for _, o := range envOverrides {
			if o.name == name {
				o.set(&after, "x")
			}
		}
		if reflect.DeepEqual(after, Config{}) {
			t.Errorf("%s changes nothing", name)
		}
	}
}

func TestAlertsConfig(t *testing.T) {
	cfg, err := Load(writeConfig(t, "data_dir: /d\nalerts:\n  on_deny: alert_rules_only\n  ntfy: {url: 'https://ntfy.sh/t', token_secret: ntfy/token}\n"), envFrom(nil))
	if err != nil || cfg.Alerts.Ntfy.URL != "https://ntfy.sh/t" || cfg.Alerts.OnDeny != "alert_rules_only" {
		t.Fatalf("%+v %v", cfg.Alerts, err)
	}
	for name, body := range map[string]string{
		"bad on_deny":  "data_dir: /d\nalerts: {on_deny: some}\n",
		"no url":       "data_dir: /d\nalerts: {ntfy: {token_secret: x}}\n",
		"inline token": "data_dir: /d\nalerts: {ntfy: {url: 'https://x', token: abc}}\n",
	} {
		if _, err := Load(writeConfig(t, body), envFrom(nil)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	cfg, _ = Load("", envFrom(map[string]string{"VALET_DATA_DIR": "/d", "VALET_ALERTS_NTFY_URL": "https://ntfy.sh/x"}))
	if cfg.Alerts.Ntfy == nil || cfg.Alerts.Ntfy.URL != "https://ntfy.sh/x" {
		t.Errorf("env: %+v", cfg.Alerts)
	}
}

func TestEgressConfig(t *testing.T) {
	cfg, err := Load(writeConfig(t, "data_dir: /d\negress:\n  allow: [registry.npmjs.org, '*.pythonhosted.org', proxy.golang.org]\n"), envFrom(nil))
	if err != nil || len(cfg.Egress.Allow) != 3 || !reflect.DeepEqual(cfg.Egress.Ports, []int{443}) {
		t.Fatalf("%+v %v", cfg.Egress, err)
	}
	for _, bad := range []string{"'*'", "'*.com.'", "Registry.NPMjs.org", "10.0.0.1", "'[::1]'", "npmjs.org:443", "'**.x.org'", "'x.*.org'", "localhost", "'-x.org'"} {
		if _, err := Load(writeConfig(t, "data_dir: /d\negress: {allow: ["+bad+"]}\n"), envFrom(nil)); err == nil {
			t.Errorf("egress.allow %s accepted", bad)
		}
	}
	if _, err := Load(writeConfig(t, "data_dir: /d\negress: {ports: [0]}\n"), envFrom(nil)); err == nil {
		t.Error("port 0 accepted")
	}
	cfg, _ = Load("", envFrom(map[string]string{"VALET_DATA_DIR": "/d", "VALET_EGRESS_ALLOW": "pypi.org, *.golang.org,"}))
	if !reflect.DeepEqual(cfg.Egress.Allow, []string{"pypi.org", "*.golang.org"}) {
		t.Errorf("env: %v", cfg.Egress.Allow)
	}
}

func TestEnrollmentConfig(t *testing.T) {
	cfg, err := Load(writeConfig(t, "data_dir: /d\nenrollment: {code_ttl: 5m, replay_window: 0s, max_replays: 2}\n"), envFrom(nil))
	if err != nil || cfg.Enrollment.CodeTTL != 5*time.Minute || cfg.Enrollment.ReplayWindow == nil || *cfg.Enrollment.ReplayWindow != 0 || *cfg.Enrollment.MaxReplays != 2 {
		t.Fatalf("%+v %v", cfg.Enrollment, err)
	}
	if _, err := Load(writeConfig(t, "data_dir: /d\nenrollment: {code_ttl: soon}\n"), envFrom(nil)); err == nil {
		t.Error("a bad duration loaded")
	}
}

func TestStrictParsing(t *testing.T) {
	tests := map[string]string{
		"unknown top-level key": "data_dir: /d\ndata_dri: /typo\n",
		"unknown nested key":    "data_dir: /d\nlisten:\n  admn: :1\n",
		"inline secret value":   "data_dir: /d\nmaster_key:\n  value: hunter2\n",
		"duplicate key":         "data_dir: /a\ndata_dir: /b\n",
		"second document":       "data_dir: /a\n---\ndata_dir: /b\n",
		"wrong type":            "data_dir: [1, 2]\n",
		"not a mapping":         "- data_dir\n",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, body), envFrom(nil)); err == nil {
				t.Fatal("Load succeeded, want an error")
			}
		})
	}
}

func TestUnknownKeyErrorNamesTheKey(t *testing.T) {
	_, err := Load(writeConfig(t, "data_dir: /d\nlisten:\n  admn: :1\n"), envFrom(nil))
	if err == nil || !strings.Contains(err.Error(), "admn") {
		t.Fatalf("err = %v, want it to name the unknown key", err)
	}
}

func TestEmptyFileUsesEnv(t *testing.T) {
	cfg, err := Load(writeConfig(t, ""), envFrom(map[string]string{"VALET_DATA_DIR": "/d"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != "/d" {
		t.Fatalf("DataDir = %q", cfg.DataDir)
	}
}

func TestMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml"), envFrom(nil)); err == nil {
		t.Fatal("Load succeeded, want an error")
	}
}

func TestValidate(t *testing.T) {
	tests := map[string]struct {
		body    string
		wantErr string
	}{
		"no data dir":        {"log: {level: info}\n", "data_dir is required"},
		"bad listen address": {"data_dir: /d\nlisten: {admin: localhost}\n", "listen.admin"},
		"same address twice": {"data_dir: /d\nlisten: {agent: ':9000', egress: ':9000'}\n", "both listen on"},
		"two key sources":    {"data_dir: /d\nmaster_key: {file: /k, env: VALET_KEY}\n", "not both"},
		"bad log level":      {"data_dir: /d\nlog: {level: loud}\n", "log.level"},
		"bad log format":     {"data_dir: /d\nlog: {format: xml}\n", "log.format"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tt.body), envFrom(nil))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestPortZeroMayRepeat(t *testing.T) {
	body := "data_dir: /d\nlisten: {admin: '127.0.0.1:0', agent: '127.0.0.1:0', egress: '127.0.0.1:0'}\n"
	if _, err := Load(writeConfig(t, body), envFrom(nil)); err != nil {
		t.Fatal(err)
	}
}

func TestValidateReportsAllProblems(t *testing.T) {
	_, err := Load(writeConfig(t, "log: {level: loud, format: xml}\n"), envFrom(nil))
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"data_dir", "log.level", "log.format"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, missing %q", err, want)
		}
	}
}

// The example in the repo root must stay loadable.
func TestExampleConfigLoads(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "valet.example.yaml"), envFrom(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir == "" || cfg.MasterKey.File == "" {
		t.Fatalf("example lost its settings: %+v", cfg)
	}
}
