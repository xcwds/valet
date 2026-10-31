package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/xcwds/valet/internal/config"
	"github.com/xcwds/valet/internal/daemon"
	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/store"
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

	if err := daemon.Run(ctx, cfg, log, daemon.Options{Health: st.Ping}); err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valetd: %v\n", err)
		return ExitError
	}
	return ExitOK
}
