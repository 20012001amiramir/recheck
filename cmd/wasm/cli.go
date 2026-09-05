//go:build js && wasm && !nocli

package main

import (
	"os"

	"github.com/20012001amiramir/recheck/cli"
)

// runCLI runs the command line when the host named the program in argv, and reports whether it
// did. The Go runtime's default argv is ["js"], which is what a page gets.
func runCLI() (int, bool) {
	if len(os.Args) == 0 || os.Args[0] == "js" {
		return 0, false
	}
	return cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr), true
}
