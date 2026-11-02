// Command gate is the authentication and authorization service.
// Run `gate --help` for the available commands.
//
// Build it with `make build`, or `go build -o gate ./cmd`: without
// -o, Go names the binary after this directory ("cmd").
package main

import (
	"os"

	"github.com/MhmdRyhn/gate/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
