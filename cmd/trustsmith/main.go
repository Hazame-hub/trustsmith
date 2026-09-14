// Command trustsmith is the Trustsmith command-line interface.
package main

import (
	"os"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/cli"
)

// version is set at release build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// The real clock is wired here and nowhere else; everything below takes
	// the inspection time as an input.
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, cli.Env{Now: time.Now, Version: version}))
}
