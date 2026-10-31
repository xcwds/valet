package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/store"
)

// auditCmd: valet audit tail|verify. Both read the database in the data
// directory directly (read-only, without valetd's lock), so they work while
// valetd runs and need no admin API; the data directory's permissions decide
// who may read the log. The admin API version comes with operator auth (#9).
func auditCmd(ctx context.Context, args []string, sys IO) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(sys.Stderr, auditUsage)
		return ExitUsage
	}
	switch args[0] {
	case "tail":
		return auditTailCmd(ctx, args[1:], sys)
	case "verify":
		return auditVerifyCmd(ctx, args[1:], sys)
	case "-h", "-help", "--help", "help":
		_, _ = fmt.Fprint(sys.Stdout, auditUsage)
		return ExitOK
	default:
		_, _ = fmt.Fprintf(sys.Stderr, "valet audit: unknown subcommand %q\n\n%s", args[0], auditUsage)
		return ExitUsage
	}
}

const auditUsage = `Usage: valet audit <subcommand> [flags]

Subcommands:
  tail     Print recent audit events as JSON lines, oldest first
  verify   Check the hash chain; exits 1 if it is broken

Both read the database in --data-dir (default $VALET_DATA_DIR) directly,
and work while valetd is running.
`

func dataDirFlag(fs interface {
	String(name, value, usage string) *string
}, getenv Env,
) *string {
	return fs.String("data-dir", getenv("VALET_DATA_DIR"), "valetd's data directory (default $VALET_DATA_DIR)")
}

// openAuditDB opens the data directory's database read-only; on failure it
// reports the error and returns a nil db and the exit code.
func openAuditDB(ctx context.Context, name, dataDir string, sys IO) (*sql.DB, int) {
	if dataDir == "" {
		_, _ = fmt.Fprintf(sys.Stderr, "%s: --data-dir or $VALET_DATA_DIR is required\n", name)
		return nil, ExitUsage
	}
	db, err := store.OpenReadOnly(ctx, dataDir)
	if err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "%s: %v\n", name, err)
		return nil, ExitError
	}
	return db, ExitOK
}

func auditTailCmd(ctx context.Context, args []string, sys IO) int {
	fs := newFlagSet("valet audit tail", sys.Stderr)
	dataDir := dataDirFlag(fs, sys.Getenv)
	job := fs.String("job", "", "only events for this job")
	decision := fs.String("decision", "", "only events with this decision (allow, deny, require_approval, …)")
	n := fs.Int("n", 20, "how many of the most recent events")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if *n <= 0 {
		_, _ = fmt.Fprintln(sys.Stderr, "valet audit tail: -n must be positive")
		return ExitUsage
	}
	db, code := openAuditDB(ctx, "valet audit tail", *dataDir, sys)
	if db == nil {
		return code
	}
	defer func() { _ = db.Close() }()

	recs, err := audit.Tail(ctx, db, audit.Filter{JobID: *job, Decision: *decision, Limit: *n})
	if err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valet audit tail: %v\n", err)
		return ExitError
	}
	enc := json.NewEncoder(sys.Stdout)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			return ExitError
		}
	}
	return ExitOK
}

func auditVerifyCmd(ctx context.Context, args []string, sys IO) int {
	fs := newFlagSet("valet audit verify", sys.Stderr)
	dataDir := dataDirFlag(fs, sys.Getenv)
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	db, code := openAuditDB(ctx, "valet audit verify", *dataDir, sys)
	if db == nil {
		return code
	}
	defer func() { _ = db.Close() }()

	res, err := audit.Verify(ctx, db)
	if err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valet audit verify: %v\n", err)
		return ExitError
	}
	if !res.OK() {
		_, _ = fmt.Fprintf(sys.Stdout, "BROKEN at seq %d: %s (%d events checked)\n", res.BrokenSeq, res.Reason, res.Count)
		return ExitError
	}
	_, _ = fmt.Fprintf(sys.Stdout, "ok: %d events, chain intact through seq %d\n", res.Count, res.LastSeq)
	return ExitOK
}
