#!/usr/bin/env node
"use strict";
// `exhibitb` / `recheck` on npm: runs recheck.wasm under Node with the arguments you typed, so
// `npx exhibitb verify receipt.json` is the same verifier as the native binary. Files are read
// from the current directory; the exit code is the verifier's (0 pass, 1 fail, 2 incomplete,
// 64 usage). The only network use is what the command itself documents — `verify <receipt id>`
// and `--refetch` — never anything else.

const fs = require("fs");
const os = require("os");
const path = require("path");

const major = Number(process.versions.node.split(".")[0]);
if (!(major >= 18)) {
  process.stderr.write(`exhibitb: Node 18 or newer is required (this is ${process.version})\n`);
  process.exit(64);
}

// wasm_exec.js uses these when present. Node 18 has all of them but the WebCrypto global.
globalThis.fs = fs;
if (!globalThis.crypto) globalThis.crypto = require("crypto").webcrypto;

require(path.join(__dirname, "..", "wasm", "wasm_exec.js"));

const go = new Go();
go.argv = ["exhibitb", ...process.argv.slice(2)];
go.env = Object.assign({ TMPDIR: os.tmpdir() }, process.env);
go.exit = (code) => process.exit(code);

const wasmPath = path.join(__dirname, "..", "wasm", "recheck.wasm");
WebAssembly.instantiate(fs.readFileSync(wasmPath), go.importObject)
  .then((result) => {
    process.on("exit", (code) => {
      // Node exits when nothing is pending; if the module is still parked, let it report why.
      if (code === 0 && !go.exited) {
        go._pendingEvent = { id: 0 };
        go._resume();
      }
    });
    return go.run(result.instance);
  })
  .catch((err) => {
    process.stderr.write(`exhibitb: ${err && err.message ? err.message : err}\n`);
    process.exit(70);
  });
