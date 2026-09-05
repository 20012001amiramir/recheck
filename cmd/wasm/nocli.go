//go:build js && wasm && nocli

package main

// runCLI never runs in the page's module: there is no command line in it.
func runCLI() (int, bool) { return 0, false }
