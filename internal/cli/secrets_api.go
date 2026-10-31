package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/tabwriter"

	"github.com/xcwds/valet/internal/secrets"
)

// secretPath escapes each segment of a validated secret name.
func secretPath(name string) string {
	segs := strings.Split(name, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return "api/secrets/" + strings.Join(segs, "/")
}

// secretsSetCmd reads the value from stdin, never from argv, so it stays out
// of shell history and ps.
func secretsSetCmd(ctx context.Context, args []string, sys IO) int {
	fs := newFlagSet("valet secrets set", sys.Stderr)
	conn := addAdminFlags(fs, sys.Getenv)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(fs.Output(), "Usage: valet secrets set NAME < value-file")
		fs.PrintDefaults()
	}
	pos, code, ok := parseArgs(fs, args, 1)
	if !ok {
		return code
	}
	if err := secrets.ValidateName(pos[0]); err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valet secrets set: %v\n", err)
		return ExitUsage
	}
	if sys.Stdin == nil {
		_, _ = fmt.Fprintln(sys.Stderr, "valet secrets set: the value is read from stdin")
		return ExitUsage
	}
	value, err := io.ReadAll(io.LimitReader(sys.Stdin, secrets.MaxSecretSize+1))
	if err != nil {
		return fail(sys, "valet secrets set", err)
	}
	defer clear(value)
	value = bytes.TrimSuffix(value, []byte("\n")) // one trailing newline from echo or a file
	if len(value) == 0 {
		_, _ = fmt.Fprintln(sys.Stderr, "valet secrets set: empty value on stdin")
		return ExitUsage
	}
	if len(value) > secrets.MaxSecretSize {
		_, _ = fmt.Fprintf(sys.Stderr, "valet secrets set: value is larger than %d bytes\n", secrets.MaxSecretSize)
		return ExitUsage
	}
	c, err := conn.client(sys.Getenv)
	if err != nil {
		return fail(sys, "valet secrets set", err)
	}
	if err := c.do(ctx, http.MethodPut, secretPath(pos[0]), bytes.NewReader(value), "application/octet-stream", nil); err != nil {
		return fail(sys, "valet secrets set", err)
	}
	_, _ = fmt.Fprintf(sys.Stdout, "stored %s (%d bytes)\n", pos[0], len(value))
	return ExitOK
}

func secretsListCmd(ctx context.Context, args []string, sys IO) int {
	fs := newFlagSet("valet secrets list", sys.Stderr)
	asJSON := fs.Bool("json", false, "print JSON")
	conn := addAdminFlags(fs, sys.Getenv)
	if _, code, ok := parseArgs(fs, args, 0); !ok {
		return code
	}
	c, err := conn.client(sys.Getenv)
	if err != nil {
		return fail(sys, "valet secrets list", err)
	}
	var resp struct {
		Secrets []struct {
			Name      string `json:"name"`
			UpdatedAt string `json:"updated_at"`
		} `json:"secrets"`
	}
	if err := c.do(ctx, http.MethodGet, "api/secrets", nil, "", &resp); err != nil {
		return fail(sys, "valet secrets list", err)
	}
	if *asJSON {
		_ = json.NewEncoder(sys.Stdout).Encode(resp.Secrets)
		return ExitOK
	}
	tw := tabwriter.NewWriter(sys.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tUPDATED")
	for _, s := range resp.Secrets {
		_, _ = fmt.Fprintf(tw, "%s\t%s\n", s.Name, s.UpdatedAt)
	}
	_ = tw.Flush()
	return ExitOK
}

func secretsDeleteCmd(ctx context.Context, args []string, sys IO) int {
	fs := newFlagSet("valet secrets delete", sys.Stderr)
	conn := addAdminFlags(fs, sys.Getenv)
	pos, code, ok := parseArgs(fs, args, 1)
	if !ok {
		return code
	}
	if err := secrets.ValidateName(pos[0]); err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valet secrets delete: %v\n", err)
		return ExitUsage
	}
	c, err := conn.client(sys.Getenv)
	if err != nil {
		return fail(sys, "valet secrets delete", err)
	}
	if err := c.do(ctx, http.MethodDelete, secretPath(pos[0]), nil, "", nil); err != nil {
		return fail(sys, "valet secrets delete", err)
	}
	_, _ = fmt.Fprintf(sys.Stdout, "deleted %s\n", pos[0])
	return ExitOK
}
