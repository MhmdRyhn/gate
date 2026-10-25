// Command rbac-service is the authentication and authorization service.
// Run `rbac-service --help` for the available commands.
package main

import (
	"os"

	"github.com/MhmdRyhn/gate/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
