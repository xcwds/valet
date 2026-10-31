package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultAdminURL is where the CLI looks for valetd's admin API.
const DefaultAdminURL = "http://127.0.0.1:14400"

// statusTimeout bounds a status check end to end.
const statusTimeout = 5 * time.Second

// adminURL adds the --addr flag every admin API command shares.
func adminURL(fs interface {
	String(name, value, usage string) *string
}, getenv Env,
) *string {
	def := getenv("VALET_ADMIN_URL")
	if def == "" {
		def = DefaultAdminURL
	}
	return fs.String("addr", def, "valetd admin API URL (default $VALET_ADMIN_URL or "+DefaultAdminURL+")")
}

// parseAdminURL checks that addr is an http(s) base URL.
func parseAdminURL(addr string) (*url.URL, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("--addr: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("--addr: %q must be an http:// or https:// URL", addr)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("--addr: %q must not carry credentials, a query or a fragment", addr)
	}
	return u, nil
}

// statusCmd asks valetd's admin API whether it is healthy.
func statusCmd(ctx context.Context, args []string, sys IO) int {
	fs := newFlagSet("valet status", sys.Stderr)
	addr := adminURL(fs, sys.Getenv)
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	base, err := parseAdminURL(*addr)
	if err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valet status: %v\n", err)
		return ExitUsage
	}

	ctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	target := base.JoinPath("healthz").String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valet status: %v\n", err)
		return ExitError
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valet status: valetd is not reachable at %s: %v\n", base, err)
		return ExitError
	}
	defer func() { _ = resp.Body.Close() }()

	var health struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	// A health answer is tiny; a misdirected --addr must not make the CLI
	// buffer an arbitrary response.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &health) != nil || health.Status != "ok" {
		_, _ = fmt.Fprintf(sys.Stderr, "valet status: valetd at %s is unhealthy: %s %s\n",
			base, resp.Status, strings.TrimSpace(string(body)))
		return ExitError
	}
	_, _ = fmt.Fprintf(sys.Stdout, "valetd %s at %s: ok\n", health.Version, base)
	return ExitOK
}
