// Command valet is Valet's single binary: the operator and in-container CLI,
// and, when run as valetd or `valet daemon`, the broker daemon.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/xcwds/valet/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args, cli.IO{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv, Unsetenv: os.Unsetenv})
	stop()
	os.Exit(code)
}
