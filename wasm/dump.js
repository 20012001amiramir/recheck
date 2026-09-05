#!/usr/bin/env node
"use strict";
// Runs every receipt and root vector, a few malformed inputs and the tamper cases through the
// browser API of one module and prints the answers as JSON, so two builds can be compared byte
// for byte. `./build.sh smoke` diffs the page's module against the npm package's this way.
//
//   node wasm/dump.js [recheck.wasm [wasm_exec.js]]     defaults: the files next to this script

const fs = require("fs");
const path = require("path");

const wasmPath = path.resolve(process.argv[2] || path.join(__dirname, "recheck.wasm"));
const execPath = path.resolve(process.argv[3] || path.join(__dirname, "wasm_exec.js"));
const vectors = path.join(__dirname, "..", "spec", "vectors");

globalThis.fs = fs;
if (!globalThis.crypto) globalThis.crypto = require("crypto").webcrypto;
require(execPath);

// Until the dump is written, any exit is a failure — a module that dies on start may exit 0 on
// its own or leave nothing pending.
process.exitCode = 1;
let done = false;
const exit = process.exit.bind(process);
process.exit = (code) => exit(done ? code : 1);
function fail(msg) {
  process.stderr.write(`dump.js: ${msg && msg.stack ? msg.stack : msg}\n`, () => process.exit(1));
}

const vec = JSON.parse(fs.readFileSync(path.join(vectors, "receipt.json"), "utf8"));
const rootVec = JSON.parse(fs.readFileSync(path.join(vectors, "root.json"), "utf8"));
const keys = JSON.stringify([vec.key, rootVec.key]);
const text = (v) => JSON.stringify(v, null, 2) + "\n";
const receipt = text(vec.receipt);
const rootFile = text(rootVec.root_file);
const proof = text(rootVec.proofs[0]);

const cases = [
  ["receipt", receipt, {}],
  ["receipt, fixture key pinned", receipt, { keys }],
  ["receipt minified", JSON.stringify(vec.receipt), { keys }],
  ["projection", text(vec.projection), { keys }],
  ["unchained", text(vec.unchained.receipt), { keys }],
  ["root and proof", receipt, { keys, root: rootFile, proof }],
  ["root and proof, root key not pinned", receipt, { keys: JSON.stringify([vec.key]), root: rootFile, proof }],
  ["proof only", receipt, { keys, proof }],
  ["root only", receipt, { keys, root: rootFile }],
  ["pending proof", receipt, { keys, root: rootFile, proof: '{"status":"pending","roots_at":"2026-09-04T00:05:00Z"}' }],
  ["not json", "{", {}],
  ["array", "[]", {}],
  ["empty", "", {}],
  ["byte-order mark", "﻿" + receipt, { keys }],
  ["keys that do not parse", receipt, { keys: "nope" }],
  ["keys that are not text", receipt, { keys: 5 }],
];
vec.tampered.forEach((t, i) => cases.push([`tampered[${i}]`, text(t.receipt), { keys }]));

const go = new Go();
const ready = new Promise((resolve) => {
  globalThis.__recheckReady = resolve;
});

WebAssembly.instantiate(fs.readFileSync(wasmPath), go.importObject)
  .then(({ instance }) => {
    go.run(instance).then(() => fail("the module exited instead of staying resident"), fail);
    return ready;
  })
  .then((api) => {
    const out = {};
    for (const [name, input, opts] of cases) out[name] = JSON.parse(api.verify(input, opts));
    out["tamper seq"] = JSON.parse(api.tamper(receipt, receipt.replace('"seq": 1,', '"seq": 2,')));
    out["tamper whitespace"] = JSON.parse(api.tamper(receipt, JSON.stringify(vec.receipt)));
    out["tamper invalid"] = JSON.parse(api.tamper(receipt, "{"));
    out["tamper same"] = JSON.parse(api.tamper(receipt, receipt));
    out["tamper non-ascii"] = JSON.parse(api.tamper('{"a":"é","b":1}', '{"a":"é","b":2}'));
    out["tamper one argument"] = JSON.parse(api.tamper("x"));
    out["verify no argument"] = JSON.parse(api.verify());
    // Flushed before exiting: on Windows a pipe is asynchronous and exit() would drop the text.
    done = true;
    process.stdout.write(JSON.stringify(out, null, 2) + "\n", () => process.exit(0));
  })
  .catch(fail);
