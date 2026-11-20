// Command grow-secrets-exec loads a service's configuration from HashiCorp
// Vault or OpenBao (AppRole bootstrap from GROW_SECRETS_*) into the
// environment of a command, in memory only, and supervises it.
//
//	grow-secrets-exec -- node dist/main.js
//
// See README.md for flags, exit codes and the platform contract.
package main

import (
	"context"
	"os"

	"github.com/grow-codes-packages/secrets-exec/internal/cli"
)

// version is set at build time (-ldflags "-X main.version=1.2.3").
var version = "dev"

// main runs the command line with the real process environment.
func main() {
	os.Exit(cli.Main(context.Background(), version, cli.IO{
		Args:    os.Args[1:],
		Getenv:  os.Getenv,
		Environ: os.Environ,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
	}))
}
