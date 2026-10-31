// Package cli dispatches Valet's one binary.
//
// Valet ships as a single static binary (RFC decision 14). Run as `valet` it
// is the operator and in-container CLI; run as `valetd` (a symlink or a copy
// with that name) or as `valet daemon` it is the broker daemon.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/xcwds/valet/internal/version"
)

// Exit codes.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2
)

// Env is the process environment the CLI reads (os.Getenv in production).
type Env func(string) string

// IO bundles what a command needs from its process.
type IO struct {
	Stdout, Stderr io.Writer
	Getenv         Env
	// Unsetenv removes a variable from the process environment (os.Unsetenv
	// in production; tests may leave it nil).
	Unsetenv func(string) error
}

// Run executes the command line args (args[0] is the program name) and
// returns the process exit code. ctx is canceled on SIGINT or SIGTERM.
func Run(ctx context.Context, args []string, sys IO) int {
	if len(args) == 0 {
		return usage(sys.Stderr)
	}
	if isDaemonName(args[0]) {
		return daemonCmd(ctx, "valetd", args[1:], sys)
	}
	if len(args) < 2 {
		return usage(sys.Stderr)
	}
	switch cmd, rest := args[1], args[2:]; cmd {
	case "version", "-version", "--version":
		return printVersion("valet", rest, sys)
	case "daemon":
		return daemonCmd(ctx, "valet daemon", rest, sys)
	case "status":
		return statusCmd(ctx, rest, sys)
	case "secrets":
		return secretsCmd(rest, sys)
	case "job", "audit", "approve", "reject", "approvals", "session", "policy":
		return notYet(cmd, sys)
	case "help", "-h", "-help", "--help":
		_, _ = fmt.Fprint(sys.Stdout, usageText)
		return ExitOK
	default:
		_, _ = fmt.Fprintf(sys.Stderr, "valet: unknown command %q\n\n", cmd)
		return usage(sys.Stderr)
	}
}

// isDaemonName reports whether the binary was invoked as valetd. It splits on
// both path separators so a Windows path is handled on any build platform.
func isDaemonName(arg0 string) bool {
	name := arg0[strings.LastIndexAny(arg0, `/\`)+1:]
	return strings.TrimSuffix(name, ".exe") == "valetd"
}

// plannedIn says which issue brings each command that isn't built yet.
var plannedIn = map[string]string{
	"job":       "#9",
	"audit":     "#8",
	"approve":   "#23",
	"reject":    "#23",
	"approvals": "#23",
	"session":   "#19",
	"policy":    "#11",
}

func notYet(cmd string, sys IO) int {
	_, _ = fmt.Fprintf(sys.Stderr, "valet %s: not implemented yet (%s)\n", cmd, plannedIn[cmd])
	return ExitError
}

func printVersion(name string, extra []string, sys IO) int {
	if len(extra) > 0 {
		_, _ = fmt.Fprintf(sys.Stderr, "%s version: unexpected arguments %q\n", name, extra)
		return ExitUsage
	}
	if _, err := fmt.Fprintf(sys.Stdout, "%s %s\n", name, version.String()); err != nil {
		return ExitError
	}
	return ExitOK
}

// newFlagSet returns a flag set that reports errors to stderr instead of
// exiting, so commands stay testable.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parseFlags parses args and maps the result to an exit code; ok is false
// when the caller should return code immediately.
func parseFlags(fs *flag.FlagSet, args []string) (code int, ok bool) {
	err := fs.Parse(args)
	switch {
	case errors.Is(err, flag.ErrHelp):
		return ExitOK, false
	case err != nil:
		return ExitUsage, false
	case fs.NArg() > 0:
		_, _ = fmt.Fprintf(fs.Output(), "%s: unexpected arguments %q\n", fs.Name(), fs.Args())
		return ExitUsage, false
	}
	return ExitOK, true
}

func usage(w io.Writer) int {
	_, _ = fmt.Fprint(w, usageText)
	return ExitUsage
}

const usageText = `Usage: valet <command> [flags]

Commands:
  version   Print the version
  status    Ask a running valetd whether it is healthy
  secrets   Manage the secret store (init-key now; set/list/delete with #9)
  daemon    Run the broker daemon (same as running the binary as valetd)
  help      Show this help

Coming with later issues: job, audit, approve, reject, approvals, session,
policy.

Run 'valet <command> -h' for a command's flags.
`
