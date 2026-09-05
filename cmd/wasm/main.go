//go:build js && wasm

// Command wasm is recheck compiled to WebAssembly. It installs window.recheck = {version, verify,
// tamper} and stays resident; verify there runs entirely in memory and makes no request of any
// kind. Built without the nocli tag it also carries the command line of cmd/recheck, which runs
// instead when the host names the program in argv — the `exhibitb` npm wrapper sets argv to
// ["exhibitb", …], while a page leaves the Go runtime's default. Built with -tags nocli it is the
// page's module alone, without net/http and the rest of the command line, at a third of the size.
package main

import (
	"encoding/json"
	"os"
	"syscall/js"

	"github.com/20012001amiramir/recheck/internal/build"
	"github.com/20012001amiramir/recheck/receipt"
	"github.com/20012001amiramir/recheck/tamper"
	"github.com/20012001amiramir/recheck/verify"
)

func main() {
	if code, ran := runCLI(); ran {
		os.Exit(code)
	}
	api := js.ValueOf(map[string]any{
		"version": build.Version,
		"verify":  js.FuncOf(verifyJS),
		"tamper":  js.FuncOf(tamperJS),
	})
	js.Global().Set("recheck", api)
	if ready := js.Global().Get("__recheckReady"); ready.Type() == js.TypeFunction {
		ready.Invoke(api)
	}
	select {} // stay resident: the functions above are called from JavaScript
}

func usage(msg string) any { return string(verify.Usage(msg).JSON()) }

// verifyJS is window.recheck.verify(receiptJson, opts?): opts may carry keys, root and proof, each
// as the text of the file it stands for. The answer is the --json report of the command line.
func verifyJS(_ js.Value, args []js.Value) any {
	if len(args) < 1 || args[0].Type() != js.TypeString {
		return usage("verify(receiptJson, opts?) needs the receipt text as a string")
	}
	keys, err := receipt.Pinned()
	if err != nil {
		return usage("compiled-in keys: " + err.Error())
	}
	opts := verify.Options{Keys: keys}
	if len(args) > 1 && args[1].Type() == js.TypeObject {
		o := args[1]
		if k := o.Get("keys"); k.Type() == js.TypeString {
			extra, err := receipt.ParseKeySet([]byte(k.String()))
			if err != nil {
				return usage("keys: " + err.Error())
			}
			if err := keys.Merge(extra); err != nil {
				return usage("keys: " + err.Error())
			}
		} else if k.Type() != js.TypeUndefined && k.Type() != js.TypeNull {
			return usage("opts.keys must be the text of a keys.json")
		}
		if r := o.Get("root"); r.Type() == js.TypeString {
			opts.Root = []byte(r.String())
		}
		if p := o.Get("proof"); p.Type() == js.TypeString {
			opts.Proof = []byte(p.String())
		}
	}
	return string(verify.Run([]byte(args[0].String()), opts).JSON())
}

// tamperJS is window.recheck.tamper(original, edited).
func tamperJS(_ js.Value, args []js.Value) any {
	if len(args) < 2 || args[0].Type() != js.TypeString || args[1].Type() != js.TypeString {
		return `{"error":"tamper(original, edited) needs two strings"}`
	}
	out, err := json.Marshal(tamper.Tamper(args[0].String(), args[1].String()))
	if err != nil {
		return `{"error":"tamper: ` + err.Error() + `"}`
	}
	return string(out)
}
