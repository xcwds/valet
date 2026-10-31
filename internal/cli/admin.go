package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/operator"
	"github.com/xcwds/valet/internal/store"
)

func adminCmd(ctx context.Context, args []string, sys IO) int {
	if len(args) == 0 || args[0] != "reset-token" {
		_, _ = fmt.Fprint(sys.Stderr, adminUsage)
		return ExitUsage
	}
	fs := newFlagSet("valet admin reset-token", sys.Stderr)
	dataDir := dataDirFlag(fs, sys.Getenv)
	if _, code, ok := parseArgs(fs, args[1:], 0); !ok {
		return code
	}
	if *dataDir == "" {
		_, _ = fmt.Fprintln(sys.Stderr, "valet admin reset-token: --data-dir or $VALET_DATA_DIR is required")
		return ExitUsage
	}
	// store.Open takes the data directory lock, so this refuses to run while
	// valetd does.
	st, err := store.Open(ctx, *dataDir)
	if err != nil {
		return fail(sys, "valet admin reset-token", fmt.Errorf("%w (stop valetd first)", err))
	}
	defer func() { _ = st.Close() }()
	res, err := audit.Verify(ctx, st.Read())
	if err != nil {
		return fail(sys, "valet admin reset-token", err)
	}
	if !res.OK() {
		return fail(sys, "valet admin reset-token", fmt.Errorf("the audit log is broken at seq %d; not appending to it", res.BrokenSeq))
	}
	log := audit.New(st, logging.New(io.Discard, "json", slog.LevelError))
	path, err := operator.NewService(st, log).Reset(ctx, *dataDir)
	if err != nil {
		return fail(sys, "valet admin reset-token", err)
	}
	_, _ = fmt.Fprintf(sys.Stdout, "revoked every admin token and wrote a new one to %s\n", path)
	return ExitOK
}

const adminUsage = `Usage: valet admin reset-token [--data-dir DIR]

Revokes every admin token and writes a new one to DIR/` + operator.TokenFile + `.
For an operator who lost the token; valetd must be stopped.
`
