// Command valet is Valet's single binary: the operator and in-container CLI,
// and, when run as valetd or `valet daemon`, the broker daemon.
package main

import (
	"os"

	"github.com/xcwds/valet/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args, os.Stdout, os.Stderr))
}
