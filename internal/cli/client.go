package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xcwds/valet/internal/operator"
	"github.com/xcwds/valet/internal/tokens"
)

// requestTimeout bounds an admin API call.
const requestTimeout = 30 * time.Second

// adminFlags are the connection flags every admin API command shares. The
// token is never a flag value, so it can't end up in shell history or ps.
type adminFlags struct {
	addr      *string
	tokenFile *string
}

func addAdminFlags(fs *flag.FlagSet, getenv Env) adminFlags {
	return adminFlags{
		addr: adminURL(fs, getenv),
		tokenFile: fs.String("token-file", "",
			"file holding the admin token (default $VALET_ADMIN_TOKEN, else $VALET_DATA_DIR/"+operator.TokenFile+")"),
	}
}

// adminClient calls the admin API.
type adminClient struct {
	base  *url.URL
	token string
}

func (f adminFlags) client(getenv Env) (*adminClient, error) {
	base, err := parseAdminURL(*f.addr)
	if err != nil {
		return nil, err
	}
	tok, err := adminToken(*f.tokenFile, getenv)
	if err != nil {
		return nil, err
	}
	return &adminClient{base: base, token: tok}, nil
}

// adminToken finds the operator's token: --token-file, then
// $VALET_ADMIN_TOKEN, then the file valetd wrote in $VALET_DATA_DIR.
func adminToken(file string, getenv Env) (string, error) {
	var tok, source string
	switch {
	case file != "":
		b, err := os.ReadFile(file) //nolint:gosec // The operator chooses the file.
		if err != nil {
			return "", fmt.Errorf("admin token: %w", err)
		}
		tok, source = string(b), file
	case getenv("VALET_ADMIN_TOKEN") != "":
		tok, source = getenv("VALET_ADMIN_TOKEN"), "$VALET_ADMIN_TOKEN"
	case getenv("VALET_DATA_DIR") != "":
		path := filepath.Join(getenv("VALET_DATA_DIR"), operator.TokenFile)
		b, err := os.ReadFile(path) //nolint:gosec // data_dir plus a constant.
		if err != nil {
			return "", fmt.Errorf("admin token: %w", err)
		}
		tok, source = string(b), path
	default:
		return "", errors.New("no admin token: set $VALET_ADMIN_TOKEN, pass --token-file, or set $VALET_DATA_DIR so the CLI can read " + operator.TokenFile)
	}
	tok = strings.TrimSpace(tok)
	if _, err := tokens.Parse(tokens.Admin, tok); err != nil {
		return "", fmt.Errorf("admin token from %s is not a vlt_admin_ token", source)
	}
	return tok, nil
}

// apiError is an error response from valetd.
type apiError struct {
	Status int
	Msg    string
}

func (e *apiError) Error() string { return fmt.Sprintf("%s (HTTP %d)", e.Msg, e.Status) }

// do sends a request and decodes a JSON response into out (if not nil).
func (c *adminClient) do(ctx context.Context, method, path string, body io.Reader, contentType string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.base.JoinPath(path).String(), body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("valetd is not reachable at %s: %w", c.base, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) != nil || e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		return &apiError{Status: resp.StatusCode, Msg: e.Error}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// parseArgs parses flags that may come before or after positional arguments
// (valet job show ID --addr X) and returns the positionals; ok is false when
// the caller should return code.
func parseArgs(fs *flag.FlagSet, args []string, wantArgs int) (pos []string, code int, ok bool) {
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, ExitOK, false
			}
			return nil, ExitUsage, false
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
	if len(pos) != wantArgs {
		_, _ = fmt.Fprintf(fs.Output(), "%s: want %d argument(s), got %d\n", fs.Name(), wantArgs, len(pos))
		fs.Usage()
		return nil, ExitUsage, false
	}
	return pos, ExitOK, true
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func fail(sys IO, name string, err error) int {
	_, _ = fmt.Fprintf(sys.Stderr, "%s: %v\n", name, err)
	return ExitError
}
