package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/xcwds/valet/internal/adminapi"
	"github.com/xcwds/valet/internal/alert"
	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/config"
	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/connector/builtin"
	"github.com/xcwds/valet/internal/daemon"
	"github.com/xcwds/valet/internal/gitproxy"
	"github.com/xcwds/valet/internal/jobs"
	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/mcp"
	"github.com/xcwds/valet/internal/operator"
	"github.com/xcwds/valet/internal/pipeline"
	"github.com/xcwds/valet/internal/policy"
	"github.com/xcwds/valet/internal/secrets"
	"github.com/xcwds/valet/internal/store"
	"github.com/xcwds/valet/internal/version"
	"github.com/xcwds/valet/policies"
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
	conns, err := builtin.Load(cfg.Connectors, builtin.Deps{Secrets: secretStore})
	if err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valetd: %v\n", err)
		return ExitError
	}
	// The generic git actions (git.fetch, git.push) live in core; the
	// providers' connectors supply the upstreams (#17).
	registry, err := connector.NewRegistry(append(conns, gitproxy.Actions{})...)
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
	logging.For(log, logging.Hephaestus).Info("connectors loaded", "actions", len(registry.Actions()))

	// Themis: every role and condition compiles now, or valetd doesn't start.
	pol, err := loadPolicy(cfg.Policies)
	if err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valetd: %v\n", err)
		return ExitError
	}
	themis := logging.For(log, logging.Themis)
	themis.Info("policy loaded", "source", pol.Source(), "roles", pol.Roles())
	if un := pol.Unmatched(registry.Actions()); len(un) > 0 {
		themis.Info("rules that match no registered action (a typo in a pattern denies silently)", "rules", un)
	}
	jobSvc.RequireRoles(pol.HasRole)
	pl := pipeline.New(registry, pol, auditLog, creds, log)

	// Alerts: delivered in the background, never on the request path.
	alerts, err := newAlerts(cfg.Alerts, secretStore, log)
	if err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valetd: %v\n", err)
		return ExitError
	}
	checkAlertSecrets(ctx, cfg.Alerts, secretStore, log)
	alertsDone := make(chan struct{})
	alertCtx, stopAlerts := context.WithCancel(context.WithoutCancel(ctx))
	if alerts != nil {
		pl.SetAlerter(alerts)
		go func() { alerts.Run(alertCtx); close(alertsDone) }()
	} else {
		close(alertsDone)
	}
	defer func() { stopAlerts(); <-alertsDone }()

	// Iris: MCP at /mcp on the agent port.
	iris, err := mcp.New(registry, pl, pol, log)
	if err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valetd: %v\n", err)
		return ExitError
	}
	agentMux := http.NewServeMux()
	agentMux.Handle("/mcp", iris.Handler())
	// Ariadne: git smart HTTP at /git/{provider}/{owner}/{repo}.git.
	agentMux.Handle(gitproxy.Prefix, gitproxy.New(registry, pl, log))
	agentMux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found: this port serves /mcp", http.StatusNotFound)
	})

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
		// Every request on the agent port carries a session token.
		Agent: jobSvc.RequireSession(agentMux),
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

// loadPolicy loads roles from path, or the built-in defaults when it is empty.
func loadPolicy(path string) (*policy.Policy, error) {
	if path == "" {
		return policy.LoadFS("built-in defaults", policies.Defaults)
	}
	return policy.LoadPath(path)
}

// newAlerts builds the alert dispatcher from config, or nil when no
// destination is configured.
func newAlerts(cfg config.Alerts, s alert.SecretGetter, log *slog.Logger) (*alert.Dispatcher, error) {
	var ns []alert.Notifier
	if cfg.Ntfy != nil {
		n, err := alert.NewNtfy(cfg.Ntfy.URL, cfg.Ntfy.TokenSecret, s)
		if err != nil {
			return nil, err
		}
		ns = append(ns, n)
	}
	if cfg.Webhook != nil {
		w, err := alert.NewWebhook(cfg.Webhook.URL, cfg.Webhook.TokenSecret, s)
		if err != nil {
			return nil, err
		}
		ns = append(ns, w)
	}
	if len(ns) == 0 {
		return nil, nil
	}
	return alert.New(alert.Options{OnDeny: cfg.OnDeny, LinkBase: cfg.UIURL}, logging.For(log, "alerts"), ns...), nil
}

// checkAlertSecrets warns at start when a notifier's token secret can't be
// read, so the operator learns before the first denial that alerts will
// fail. Not fatal: the secret is often stored after valetd is up.
func checkAlertSecrets(ctx context.Context, cfg config.Alerts, s alert.SecretGetter, log *slog.Logger) {
	for name, n := range map[string]*config.Notifier{"alerts.ntfy": cfg.Ntfy, "alerts.webhook": cfg.Webhook} {
		if n == nil || n.TokenSecret == "" {
			continue
		}
		if _, err := s.Get(ctx, n.TokenSecret); err != nil {
			log.Error("alert token secret unreadable; alerts will fail until it is stored", "notifier", name, "secret", n.TokenSecret, "err", err)
		}
	}
}
