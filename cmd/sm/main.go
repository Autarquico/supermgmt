// Command sm is the SuperMgmt command-line interface.
package main

import (
	"os"

	"github.com/autarquico/supermgmt/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
