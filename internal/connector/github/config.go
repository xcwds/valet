package github

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// DefaultAPIURL is GitHub's REST API.
const DefaultAPIURL = "https://api.github.com"

// Config is the github section of the connectors file.
type Config struct {
	// AppID is the GitHub App's ID (or client ID), the JWT issuer.
	AppID string `yaml:"app_id"`
	// InstallationID is the App's installation on the account whose repos
	// agents may touch.
	InstallationID int64 `yaml:"installation_id"`
	// PrivateKeySecret names the secret store entry holding the App's PEM
	// private key (valet secrets set NAME < key.pem). Never the key itself.
	PrivateKeySecret string `yaml:"private_key_secret"`
	// APIURL is the REST API base, for GitHub Enterprise Server or tests.
	APIURL string `yaml:"api_url"`
	// Permissions narrow each role's tokens; roles not listed get no token.
	// Omitted: the RFC's table (DefaultPermissions).
	Permissions map[string]map[string]string `yaml:"permissions"`
}

// DefaultPermissions is the RFC's table: what each role's token can do even
// if Valet's policy were bypassed (RFC GitHub connector, decision 4), plus
// checks: read, which github.checks.read needs.
func DefaultPermissions() map[string]map[string]string {
	return map[string]map[string]string{
		"reviewer":    {"contents": "read", "pull_requests": "write", "checks": "read", "metadata": "read"},
		"implementer": {"contents": "write", "pull_requests": "write", "checks": "read", "metadata": "read"},
		"triage":      {"issues": "write", "metadata": "read"},
	}
}

var permissionName = regexp.MustCompile(`^[a-z][a-z_]{0,63}$`)

func (c *Config) validate() error {
	var errs []string
	if c.AppID == "" {
		errs = append(errs, "app_id is required")
	}
	if c.InstallationID <= 0 {
		errs = append(errs, "installation_id is required")
	}
	if c.PrivateKeySecret == "" {
		errs = append(errs, "private_key_secret is required (the secret store name of the App's key)")
	}
	if c.APIURL == "" {
		c.APIURL = DefaultAPIURL
	}
	u, err := url.Parse(c.APIURL)
	plainLoopback := u != nil && u.Scheme == "http" && isLoopback(u.Hostname())
	if err != nil || u.Host == "" || (u.Scheme != "https" && !plainLoopback) {
		errs = append(errs, fmt.Sprintf("api_url %q: must be https (http only for loopback, in tests)", c.APIURL))
	}
	c.APIURL = strings.TrimRight(c.APIURL, "/")
	if c.Permissions == nil {
		c.Permissions = DefaultPermissions()
	}
	for role, perms := range c.Permissions {
		if len(perms) == 0 {
			errs = append(errs, fmt.Sprintf("permissions.%s: empty", role))
		}
		for name, level := range perms {
			if !permissionName.MatchString(name) {
				errs = append(errs, fmt.Sprintf("permissions.%s: bad permission name %q", role, name))
			}
			// Agents never need admin; refusing it here keeps a config
			// mistake from minting one.
			if level != "read" && level != "write" {
				errs = append(errs, fmt.Sprintf("permissions.%s.%s: %q must be read or write", role, name, level))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("github connector: %s", strings.Join(errs, "; "))
	}
	return nil
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
