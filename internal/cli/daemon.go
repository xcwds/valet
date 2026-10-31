package cli

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xcwds/valet/internal/adminapi"
	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/config"
	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/connector/builtin"
	"github.com/xcwds/valet/internal/daemon"
	"github.com/xcwds/valet/internal/jobs"
	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/operator"
	"github.com/xcwds/valet/internal/pipeline"
	"github.com/xcwds/valet/internal/secrets"
	"github.com/xcwds/valet/internal/store"
	"github.com/xcwds/valet/internal/version"
)

// daemonCmd runs valetd: valetd [--config FILE], or valetd version.
func daemonCmd(ctx context.Context, name string, args []string, sys IO) int {
	if len(args) > 0 {
		switch args[0] {
		case "version", "-version", "--version":
			return printVersion("valetd", args[1:], sys)
		}
	}

	fs := newFlagSet(name, sys.Stderr)
	configPath := fs.String("config", sys.Getenv("VALET_CONFIG"), "path to valet.yaml (default $VALET_CONFIG)")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "Usage: %s [--config FILE]\n       %s version\n\nFlags:\n", name, name)
		fs.PrintDefaults()
		_, _ = fmt.Fprintf(fs.Output(), "\nEnvironment overrides: %s\n", strings.Join(config.EnvNames(), ", "))
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	cfg, err := config.Load(*configPath, sys.Getenv)
	if err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valetd: %v\n", err)
		return ExitError
	}
	level, _ := config.ParseLevel(cfg.Log.Level) // validated by Load
	log := logging.New(sys.Stdout, cfg.Log.Format, level)

	// The master key comes first: a missing or malformed key fails before
	// the data directory is touched.
	masterKey, err := secrets.LoadMasterKey(cfg.MasterKey.File, cfg.MasterKey.Env, sys.Getenv)
	if err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valetd: %v\n", err)
		return ExitError
	}
	// Drop the key from the environment so nothing valetd starts inherits it.
	// (Linux's /proc/<pid>/environ still shows the environment valetd was
	// started with, readable by the same user and root; a key file avoids
	// that, which is why the docs prefer master_key.file.)
	if name := secrets.KeyEnvName(cfg.MasterKey.File, cfg.MasterKey.Env); name != "" {
		if sys.Unsetenv != nil {
			_ = sys.Unsetenv(name)
		}
	}

	st, err := store.Open(ctx, cfg.DataDir)
	if err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valetd: %v\n", err)
		return ExitError
	}
	defer func() {
		if err := st.Close(); err != nil {
			log.Error("closing the database", "err", err)
		}
	}()

	// Clio: refuse to append to a chain that's already broken. Someone with
	// write access to the database has edited history; that needs a person,
	// not a daemon carrying on.
	res, err := audit.Verify(ctx, st.Read())
	if err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valetd: %v\n", err)
		return ExitError
	}
	if !res.OK() {
		_, _ = fmt.Fprintf(sys.Stderr, "valetd: the audit log is broken at seq %d: %s\n"+
			"Investigate before starting (valet audit verify --data-dir %s); valetd will not append to it.\n",
			res.BrokenSeq, res.Reason, cfg.DataDir)
		return ExitError
	}
	auditLog := audit.New(st, log)
	logging.For(log, logging.Clio).Info("audit log verified", "events", res.Count)

	secretStore, err := secrets.Open(ctx, st, masterKey, auditLog)
	if err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valetd: %v\n", err)
		return ExitError
	}
	logging.For(log, logging.Hekate).Info("master key verified", "key_id", masterKey.ID())

	// Operators: make sure there is an admin token to get in with.
	ops := operator.NewService(st, auditLog)
	if path, err := ops.Bootstrap(ctx, cfg.DataDir); err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valetd: %v\n", err)
		return ExitError
	} else if path != "" {
		log.Info("created an admin token; the CLI reads it from this file", "path", path)
	}
	jobSvc := jobs.NewService(st, auditLog)

	// Hephaestus: the connectors, checked now so a bad catalog stops valetd
	// at start. The pipeline is what MCP (#14) and git (#17) will call; until
	// policy (#11) is configured it denies everything.
	registry, err := connector.NewRegistry(builtin.All()...)
	if err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valetd: %v\n", err)
		return ExitError
	}
	creds := connector.NewCache()
	jobSvc.OnRevoke(func(ctx context.Context, jobID string) {
		if err := creds.DropJob(ctx, registry, jobID); err != nil {
			log.Warn("revoking upstream credentials", "job", jobID, "err", err)
		}
	})
	go sweep(ctx, creds)
	_ = pipeline.New(registry, pipeline.DenyAll{}, auditLog, creds, log)
	logging.For(log, logging.Hephaestus).Info("connectors loaded", "actions", len(registry.Actions()))

	if _, err := auditLog.Append(ctx, audit.Event{
		Interface: audit.InterfaceSystem, Action: "valetd.start", Decision: audit.Info,
		Params: map[string]any{"version": version.String()},
	}); err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valetd: %v\n", err)
		return ExitError
	}

	runErr := daemon.Run(ctx, cfg, log, daemon.Options{
		Health: st.Ping,
		Admin: adminapi.Handler(adminapi.Deps{
			Jobs: jobSvc, Operator: ops, Secrets: secretStore, AuditDB: st.Read(), Log: log,
		}),
		// Authenticated agents still get 403 until MCP (#14) and git (#17) land.
		Agent: jobSvc.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "no agent endpoints are enabled yet", http.StatusForbidden)
		})),
	})
	stopEvent := audit.Event{Interface: audit.InterfaceSystem, Action: "valetd.stop", Decision: audit.Info}
	if runErr != nil {
		stopEvent.Error = runErr.Error()
	}
	if _, err := auditLog.Append(context.WithoutCancel(ctx), stopEvent); err != nil {
		log.Error("recording the stop", "err", err)
	}
	if runErr != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valetd: %v\n", runErr)
		return ExitError
	}
	return ExitOK
}

// sweep drops expired credentials from the cache every few minutes.
func sweep(ctx context.Context, creds *connector.Cache) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			creds.Sweep()
		}
	}
}
