package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xcwds/valet/internal/jobs"
)

// Defaults for valet session login, overridable by flag or environment.
const (
	defaultAgentURL = "http://valet:14401"
	defaultCodeFile = "/run/secrets/valet_enroll"
)

// loginBackoff is the first retry delay; tests shorten it.
var loginBackoff = time.Second

func sessionCmd(ctx context.Context, args []string, sys IO) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(sys.Stderr, sessionUsage)
		return ExitUsage
	}
	switch args[0] {
	case "login":
		return sessionLoginCmd(ctx, args[1:], sys)
	case "-h", "-help", "--help", "help":
		_, _ = fmt.Fprint(sys.Stdout, sessionUsage)
		return ExitOK
	default:
		_, _ = fmt.Fprintf(sys.Stderr, "valet session: unknown subcommand %q\n\n%s", args[0], sessionUsage)
		return ExitUsage
	}
}

const sessionUsage = `Usage: valet session <subcommand> [flags]

Subcommands:
  login   Exchange the container's one-time enrollment code for its job's
          session token, and write the token to a file (run at start-up)
`

func sessionLoginCmd(ctx context.Context, args []string, sys IO) int {
	fs := newFlagSet("valet session login", sys.Stderr)
	url := fs.String("url", envOr(sys.Getenv, "VALET_URL", defaultAgentURL), "Valet's agent URL ($VALET_URL)")
	codeFile := fs.String("code-file", envOr(sys.Getenv, "VALET_ENROLL_CODE_FILE", defaultCodeFile),
		"file holding the enrollment code ($VALET_ENROLL_CODE_FILE); deleted once Valet has answered")
	tokenFile := fs.String("token-file", envOr(sys.Getenv, "VALET_TOKEN_FILE", defaultTokenFile(sys.Getenv)),
		"where to write the session token ($VALET_TOKEN_FILE)")
	budget := fs.Duration("timeout", 2*time.Minute, "how long to keep retrying while Valet is unreachable")
	if _, code, ok := parseArgs(fs, args, 0); !ok {
		return code
	}
	const name = "valet session login"
	raw, err := os.ReadFile(*codeFile)
	if err != nil {
		return fail(sys, name, fmt.Errorf("reading the enrollment code: %w", err))
	}
	code := strings.TrimSpace(string(raw))

	resp, status, err := exchange(ctx, strings.TrimRight(*url, "/")+jobs.EnrollPath, code, *budget, sys)
	if status != 0 {
		// Valet answered: the code is spent (or refused for good), so it
		// has no further use in the container.
		if err := os.Remove(*codeFile); err != nil && !errors.Is(err, iofs.ErrNotExist) {
			_, _ = fmt.Fprintf(sys.Stderr, "%s: warning: could not delete %s: %v\n", name, *codeFile, err)
		}
	}
	if err != nil {
		return fail(sys, name, err)
	}
	if err := writeSecretFile(*tokenFile, []byte(resp.SessionToken+"\n")); err != nil {
		return fail(sys, name, fmt.Errorf("writing the session token: %w", err))
	}
	_, _ = fmt.Fprintf(sys.Stderr, "enrolled as %s until %s; session token in %s\n",
		resp.JobID, resp.ExpiresAt.Local().Format(time.RFC3339), *tokenFile)
	return ExitOK
}

// exchange posts the code until Valet gives a definitive answer, retrying
// network errors, 5xx and throttling with the same code (a retry inside
// the repeat window gets the first answer back). status is the final HTTP
// status, or 0 if Valet never answered definitively.
func exchange(ctx context.Context, url, code string, budget time.Duration, sys IO) (jobs.EnrollResponse, int, error) {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	body, _ := json.Marshal(map[string]string{"code": code})
	wait := loginBackoff
	for attempt := 1; ; attempt++ {
		var retryAfter time.Duration
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return jobs.EnrollResponse{}, 0, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			b, rerr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			switch {
			case rerr != nil:
				err = rerr // the answer was cut off: retry, it will be replayed
			case resp.StatusCode == http.StatusOK:
				var out jobs.EnrollResponse
				if err := json.Unmarshal(b, &out); err != nil || out.SessionToken == "" {
					return jobs.EnrollResponse{}, resp.StatusCode, fmt.Errorf("unexpected answer from Valet")
				}
				return out, resp.StatusCode, nil
			case resp.StatusCode == http.StatusForbidden:
				return jobs.EnrollResponse{}, resp.StatusCode, errors.New("enrollment refused: the code was already used, has expired, " +
					"or its job was revoked; ask the operator for a new one ('valet job enroll')")
			case resp.StatusCode == http.StatusTooManyRequests:
				secs, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
				retryAfter = time.Duration(secs) * time.Second
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
			case resp.StatusCode >= 500:
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
			default:
				return jobs.EnrollResponse{}, 0, fmt.Errorf("unexpected answer from Valet: HTTP %d", resp.StatusCode)
			}
		}
		delay := max(wait, retryAfter)
		_, _ = fmt.Fprintf(sys.Stderr, "valet session login: attempt %d: %v; retrying in %s\n", attempt, err, delay)
		select {
		case <-ctx.Done():
			return jobs.EnrollResponse{}, 0, fmt.Errorf("gave up reaching Valet at %s: %w", url, err)
		case <-time.After(delay):
		}
		wait = min(wait*2, 15*time.Second)
	}
}

// writeSecretFile writes b to path with mode 0600, replacing it atomically,
// creating the directory (0700) if needed.
func writeSecretFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".valet-token-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func defaultTokenFile(getenv Env) string {
	if home := getenv("HOME"); home != "" {
		return filepath.Join(home, ".valet", "token")
	}
	return ".valet/token"
}

func envOr(getenv Env, name, def string) string {
	if v := getenv(name); v != "" {
		return v
	}
	return def
}
