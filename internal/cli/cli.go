// Package cli dispatches Valet's one binary.
//
// Valet ships as a single static binary (RFC decision 14). Run as `valet` it
// is the operator and in-container CLI; run as `valetd` (a symlink or a copy
// with that name) or as `valet daemon` it is the broker daemon.
package cli

import (
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

// Run executes the command line args (args[0] is the program name) and
// returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usage(stderr)
	}
	if isDaemonName(args[0]) {
		return daemon(args[1:], stdout, stderr)
	}
	if len(args) < 2 {
		return usage(stderr)
	}
	switch cmd, rest := args[1], args[2:]; cmd {
	case "version", "-version", "--version":
		return printVersion("valet", rest, stdout, stderr)
	case "daemon":
		return daemon(rest, stdout, stderr)
	case "help", "-h", "-help", "--help":
		_, _ = fmt.Fprint(stdout, usageText)
		return ExitOK
	default:
		_, _ = fmt.Fprintf(stderr, "valet: unknown command %q\n\n", cmd)
		return usage(stderr)
	}
}

// isDaemonName reports whether the binary was invoked as valetd. It splits on
// both path separators so a Windows path is handled on any build platform.
func isDaemonName(arg0 string) bool {
	name := arg0[strings.LastIndexAny(arg0, `/\`)+1:]
	return strings.TrimSuffix(name, ".exe") == "valetd"
}

// daemon is the valetd entry point. Until the daemon exists (#5) it only
// reports its version, and refuses anything else rather than pretending to run.
func daemon(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return printVersion("valetd", nil, stdout, stderr)
	}
	switch args[0] {
	case "version", "-version", "--version":
		return printVersion("valetd", args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "valetd: %q is not supported yet; the daemon arrives with #5\n", args[0])
		return ExitUsage
	}
}

func printVersion(name string, extra []string, stdout, stderr io.Writer) int {
	if len(extra) > 0 {
		_, _ = fmt.Fprintf(stderr, "%s version: unexpected arguments %q\n", name, extra)
		return ExitUsage
	}
	if _, err := fmt.Fprintf(stdout, "%s %s\n", name, version.String()); err != nil {
		return ExitError
	}
	return ExitOK
}

func usage(w io.Writer) int {
	_, _ = fmt.Fprint(w, usageText)
	return ExitUsage
}

const usageText = `Usage: valet <command>

Commands:
  version   Print the version
  daemon    Run the broker daemon (same as running the binary as valetd)
  help      Show this help
`
