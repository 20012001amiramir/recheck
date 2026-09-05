// Command recheck verifies EXHIBIT B receipts offline. The same binary ships as `exhibitb`.
package main

import (
	"os"

	"github.com/20012001amiramir/recheck/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
