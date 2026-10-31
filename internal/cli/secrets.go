package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/xcwds/valet/internal/secrets"
)

// secretsCmd: valet secrets init-key [--out FILE]. Setting, listing and
// deleting secrets go through the admin API, which needs operator auth (#9).
func secretsCmd(args []string, sys IO) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(sys.Stderr, secretsUsage)
		return ExitUsage
	}
	switch args[0] {
	case "init-key":
		return initKeyCmd(args[1:], sys)
	case "set", "list", "delete":
		_, _ = fmt.Fprintf(sys.Stderr, "valet secrets %s: not implemented yet; it needs the admin API's operator auth (#9)\n", args[0])
		return ExitError
	case "-h", "-help", "--help", "help":
		_, _ = fmt.Fprint(sys.Stdout, secretsUsage)
		return ExitOK
	default:
		_, _ = fmt.Fprintf(sys.Stderr, "valet secrets: unknown subcommand %q\n\n%s", args[0], secretsUsage)
		return ExitUsage
	}
}

//nolint:gosec // Help text, not a credential.
const secretsUsage = `Usage: valet secrets <subcommand>

Subcommands:
  init-key [--out FILE]   Generate a master key (base64). With --out, write it
                          to a new file with mode 0600; otherwise print it.

Coming with operator auth (#9): set, list, delete.
`

func initKeyCmd(args []string, sys IO) int {
	fs := newFlagSet("valet secrets init-key", sys.Stderr)
	out := fs.String("out", "", "write the key to this new file (mode 0600) instead of stdout")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	key, err := secrets.NewMasterKey()
	if err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valet secrets init-key: %v\n", err)
		return ExitError
	}
	if *out == "" {
		_, _ = fmt.Fprintln(sys.Stdout, key)
		return ExitOK
	}
	if err := writeNewFile(*out, []byte(key+"\n")); err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valet secrets init-key: %v\n", err)
		return ExitError
	}
	_, _ = fmt.Fprintf(sys.Stderr, "wrote a new master key to %s\nKeep a backup: without it, stored secrets can't be decrypted.\n", *out)
	return ExitOK
}

// writeNewFile creates path with mode 0600 and writes b, refusing to replace
// an existing file (overwriting a master key would orphan every secret).
func writeNewFile(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // The operator chooses the path.
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s already exists; refusing to overwrite a key", path)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
