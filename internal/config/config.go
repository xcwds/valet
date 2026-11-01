// Package config loads valetd's settings from a YAML file and VALET_*
// environment variables.
//
// Parsing is strict: an unknown key, a duplicate key or a second YAML document
// is an error, because a typo in a security setting must not silently weaken
// it. Secrets are never written in the file; it names where they come from.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Default listen addresses (RFC Architecture). The admin port defaults to
// loopback; a deployment binds it to the egress network explicitly.
const (
	DefaultAdminAddr  = "127.0.0.1:14400"
	DefaultAgentAddr  = ":14401"
	DefaultEgressAddr = ":14402"
)

// Config is valetd's configuration.
type Config struct {
	// DataDir holds the database and other state. Required.
	DataDir string `yaml:"data_dir"`
	// Listen holds the address of each listener.
	Listen Listen `yaml:"listen"`
	// MasterKey says where the secret store's master key comes from (#7).
	MasterKey MasterKey `yaml:"master_key"`
	// Log configures logging.
	Log Log `yaml:"log"`
	// Policies is the path to the role and policy files (#11).
	Policies string `yaml:"policies"`
	// Connectors is the path to the connector configuration (#10).
	Connectors string `yaml:"connectors"`
	// Alerts configures where denials are reported (#15).
	Alerts Alerts `yaml:"alerts"`
	// Egress configures Charon, the registry egress proxy (#18).
	Egress Egress `yaml:"egress"`
	// Enrollment tunes container enrollment codes (#19).
	Enrollment Enrollment `yaml:"enrollment"`
}

// Enrollment tunes the one-time codes containers exchange for their
// session. Unset fields take the defaults (10m, 60s, 5).
type Enrollment struct {
	// CodeTTL is how long a code stays usable for its first use.
	CodeTTL time.Duration `yaml:"code_ttl"`
	// ReplayWindow is how long after first use a retry with the same code
	// gets the same response (at most 5m; 0 turns retries off).
	ReplayWindow *time.Duration `yaml:"replay_window"`
	// MaxReplays caps those retries per code.
	MaxReplays *int `yaml:"max_replays"`
}

// Egress says where agents may open tunnels. Empty Allow denies every
// CONNECT (RFC decision 5).
type Egress struct {
	// Allow lists host names (registry.npmjs.org) and suffix patterns
	// (*.pythonhosted.org, which matches subdomains only).
	Allow []string `yaml:"allow"`
	// Ports agents may CONNECT to. Default [443].
	Ports []int `yaml:"ports"`
}

// egressPattern is a lowercase DNS name, optionally behind "*.".
var egressPattern = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

// Alerts says where to send alerts and which decisions alert.
type Alerts struct {
	// OnDeny is "all" (every deny alerts; the default) or
	// "alert_rules_only" (only rules marked alert: true).
	OnDeny string `yaml:"on_deny"`
	// UIURL is the admin UI's base URL, for links in alerts. Optional.
	UIURL string `yaml:"ui_url"`
	// Ntfy publishes to an ntfy topic.
	Ntfy *Notifier `yaml:"ntfy"`
	// Webhook POSTs each alert as JSON.
	Webhook *Notifier `yaml:"webhook"`
}

// Notifier is one alert destination.
type Notifier struct {
	URL string `yaml:"url"`
	// TokenSecret names a secret store entry sent as a Bearer token.
	TokenSecret string `yaml:"token_secret"`
}

// Listen holds the listener addresses.
type Listen struct {
	// Admin serves the operator API and UI. Never reachable from agentnet.
	Admin string `yaml:"admin"`
	// Agent serves MCP (/mcp) and the git proxy (/git/...).
	Agent string `yaml:"agent"`
	// Egress is the registry egress proxy.
	Egress string `yaml:"egress"`
}

// MasterKey names the source of the master key: a file, or an environment
// variable. At most one is set; the key itself never appears in the config.
type MasterKey struct {
	// File is a path to a file holding the key (e.g. a Docker secret).
	File string `yaml:"file"`
	// Env is the name of an environment variable holding the key.
	Env string `yaml:"env"`
}

// Log configures logging.
type Log struct {
	// Level is debug, info, warn or error.
	Level string `yaml:"level"`
	// Format is json or text.
	Format string `yaml:"format"`
}

// Environment variables that override the file. Each maps to one setting.
var envOverrides = []struct {
	name string
	set  func(*Config, string)
}{
	{"VALET_DATA_DIR", func(c *Config, v string) { c.DataDir = v }},
	{"VALET_ADMIN_ADDR", func(c *Config, v string) { c.Listen.Admin = v }},
	{"VALET_AGENT_ADDR", func(c *Config, v string) { c.Listen.Agent = v }},
	{"VALET_EGRESS_ADDR", func(c *Config, v string) { c.Listen.Egress = v }},
	{"VALET_MASTER_KEY_FILE", func(c *Config, v string) { c.MasterKey.File = v }},
	{"VALET_MASTER_KEY_ENV", func(c *Config, v string) { c.MasterKey.Env = v }},
	{"VALET_LOG_LEVEL", func(c *Config, v string) { c.Log.Level = v }},
	{"VALET_LOG_FORMAT", func(c *Config, v string) { c.Log.Format = v }},
	{"VALET_POLICIES", func(c *Config, v string) { c.Policies = v }},
	{"VALET_CONNECTORS", func(c *Config, v string) { c.Connectors = v }},
	{"VALET_EGRESS_ALLOW", func(c *Config, v string) { c.Egress.Allow = splitList(v) }},
	{"VALET_ALERTS_NTFY_URL", func(c *Config, v string) {
		if c.Alerts.Ntfy == nil {
			c.Alerts.Ntfy = &Notifier{}
		}
		c.Alerts.Ntfy.URL = v
	}},
}

// EnvNames lists the environment variables Load reads, for help text.
func EnvNames() []string {
	names := make([]string, len(envOverrides))
	for i, o := range envOverrides {
		names[i] = o.name
	}
	return names
}

// Load reads the config file at path (if path is not empty), applies
// environment overrides from getenv, fills defaults and validates the result.
func Load(path string, getenv func(string) string) (*Config, error) {
	cfg := &Config{}
	if path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // The operator chooses the config path.
		if err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
		if err := parse(data, cfg); err != nil {
			return nil, fmt.Errorf("config %s: %w", path, err)
		}
	}
	for _, o := range envOverrides {
		if v := getenv(o.name); v != "" {
			o.set(cfg, v)
		}
	}
	cfg.setDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// parse decodes one strict YAML document into cfg. An empty file is allowed.
func parse(data []byte, cfg *Config) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("only one YAML document is allowed")
	}
	return nil
}

func (c *Config) setDefaults() {
	if c.Listen.Admin == "" {
		c.Listen.Admin = DefaultAdminAddr
	}
	if c.Listen.Agent == "" {
		c.Listen.Agent = DefaultAgentAddr
	}
	if c.Listen.Egress == "" {
		c.Listen.Egress = DefaultEgressAddr
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "json"
	}
	if len(c.Egress.Ports) == 0 {
		c.Egress.Ports = []int{443}
	}
}

// splitList splits a comma-separated environment value.
func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Validate reports every problem with the config at once.
func (c *Config) Validate() error {
	var errs []error
	if c.DataDir == "" {
		errs = append(errs, errors.New("data_dir is required (or set VALET_DATA_DIR)"))
	}
	addrs := map[string]string{}
	for _, l := range []struct{ name, addr string }{
		{"listen.admin", c.Listen.Admin},
		{"listen.agent", c.Listen.Agent},
		{"listen.egress", c.Listen.Egress},
	} {
		_, port, err := net.SplitHostPort(l.addr)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %q is not host:port: %w", l.name, l.addr, err))
			continue
		}
		if port == "0" {
			continue // any free port; never a clash
		}
		if other, dup := addrs[l.addr]; dup {
			errs = append(errs, fmt.Errorf("%s and %s both listen on %q", other, l.name, l.addr))
		}
		addrs[l.addr] = l.name
	}
	if c.MasterKey.File != "" && c.MasterKey.Env != "" {
		errs = append(errs, errors.New("master_key: set file or env, not both"))
	}
	if _, err := ParseLevel(c.Log.Level); err != nil {
		errs = append(errs, err)
	}
	switch c.Alerts.OnDeny {
	case "", "all", "alert_rules_only":
	default:
		errs = append(errs, fmt.Errorf("alerts.on_deny: %q must be all or alert_rules_only", c.Alerts.OnDeny))
	}
	for name, n := range map[string]*Notifier{"alerts.ntfy": c.Alerts.Ntfy, "alerts.webhook": c.Alerts.Webhook} {
		if n != nil && n.URL == "" {
			errs = append(errs, fmt.Errorf("%s.url is required", name))
		}
	}
	for _, h := range c.Egress.Allow {
		if !egressPattern.MatchString(h) {
			errs = append(errs, fmt.Errorf("egress.allow: %q must be a lowercase host name or *.suffix (no IP addresses, ports or bare *)", h))
		}
	}
	for _, p := range c.Egress.Ports {
		if p < 1 || p > 65535 {
			errs = append(errs, fmt.Errorf("egress.ports: %d is not a port", p))
		}
	}
	if c.Log.Format != "json" && c.Log.Format != "text" {
		errs = append(errs, fmt.Errorf("log.format: %q must be json or text", c.Log.Format))
	}
	if len(errs) > 0 {
		return fmt.Errorf("config: %w", errors.Join(errs...))
	}
	return nil
}

// ParseLevel parses a log level name.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("log.level: %q must be debug, info, warn or error", s)
	}
}
