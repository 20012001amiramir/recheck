#!/usr/bin/env node
"use strict";
// Exercises the browser API of recheck.wasm under Node. argv is left at the Go runtime's default,
// so the module installs globalThis.recheck instead of running the command line — the same path
// a page takes through recheck.js. Run by `./build.sh smoke` after `./build.sh wasm`.
//
//   node wasm/check.js [recheck.wasm [wasm_exec.js]] [--check-stamp[=VERSION]]
//                                                         defaults: the files next to this script
//
// --check-stamp insists the module's version is the one this checkout would stamp — VERSION when
// given, else the tag on HEAD, else <npm/package.json version>+<short commit id>, exactly as
// build.sh computes it — so a module built before the last commit is caught rather than shipped
// under a stale id.

const fs = require("fs");
const path = require("path");

const args = process.argv.slice(2);
const stampFlag = args.find((a) => a === "--check-stamp" || a.startsWith("--check-stamp="));
const positional = args.filter((a) => a !== stampFlag);
const wasmPath = path.resolve(positional[0] || path.join(__dirname, "recheck.wasm"));
const execPath = path.resolve(positional[1] || path.join(__dirname, "wasm_exec.js"));

function expectedStamp() {
  const explicit = stampFlag && stampFlag.includes("=") ? stampFlag.slice(stampFlag.indexOf("=") + 1) : "";
  if (explicit) return explicit;
  const { execFileSync } = require("child_process");
  const repo = path.join(__dirname, "..");
  const git = (...argv) => execFileSync("git", argv, { cwd: repo, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  try {
    return git("describe", "--tags", "--exact-match");
  } catch {
    const pkg = JSON.parse(fs.readFileSync(path.join(repo, "npm", "package.json"), "utf8"));
    return `${pkg.version}+${git("rev-parse", "--short", "HEAD")}`;
  }
}

globalThis.fs = fs;
if (!globalThis.crypto) globalThis.crypto = require("crypto").webcrypto;
require(execPath);

const vectors = path.join(__dirname, "..", "spec", "vectors");
const receipt = fs.readFileSync(path.join(vectors, "receipt-valid.json"), "utf8");
const keys = fs.readFileSync(path.join(vectors, "test-key.json"), "utf8");
const edited = receipt.replace('"seq": 1,', '"seq": 2,');

// Until the checks have run, any exit is a failure — a module that dies on start may exit 0 on
// its own or leave nothing pending. Writes are flushed before exiting: on Windows a pipe is
// asynchronous and exit() would drop them.
process.exitCode = 1;
let done = false;
const exit = process.exit.bind(process);
process.exit = (code) => exit(done ? code : 1);
function fail(msg) {
  process.stderr.write(`check.js: ${msg && msg.stack ? msg.stack : msg}\n`, () => process.exit(1));
}
function expect(cond, what) {
  if (!cond) fail(`expected ${what}`);
}

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
    expect(api === globalThis.recheck, "__recheckReady to hand over globalThis.recheck");
    expect(typeof api.version === "string" && api.version !== "", "version to be a string");
    if (stampFlag) {
      const want = expectedStamp();
      expect(api.version === want, `the module to be stamped ${want} (it says ${api.version}: rebuild it after committing)`);
    }

    const pinnedOnly = JSON.parse(api.verify(receipt));
    const withKey = JSON.parse(api.verify(receipt, { keys }));
    const tampered = JSON.parse(api.verify(edited, { keys }));
    const notText = JSON.parse(api.verify(42));
    const diff = JSON.parse(api.tamper(receipt, edited));
    const same = JSON.parse(api.tamper(receipt, receipt));

    expect(pinnedOnly.exit === 2 && pinnedOnly.ok === true, "exit 2 with the fixture key not pinned");
    expect(withKey.exit === 0 && withKey.ok === true && withKey.checks.length === 5, "exit 0 with the fixture key passed in");
    expect(withKey.receipt && withKey.receipt.id === "eb_2m4Kq8Xr7vTb3nHd", "the receipt line");
    expect(tampered.exit === 1 && tampered.first_failure && tampered.first_failure.check === "self_hash", "exit 1 at self_hash for the tampered copy");
    expect(notText.exit === 64 && typeof notText.error === "string", "exit 64 for a receipt that is not text");
    expect(diff.changed === true && diff.path === "/seq" && diff.whitespace_only === false && diff.invalid_json === false, "tamper to point at /seq");
    expect(same.changed === false && same.offset === -1, "tamper to see no change");

    done = true;
    process.stdout.write(
      `check.js: recheck ${api.version} browser API ok in ${path.basename(wasmPath)} (verify 2/0/1/64, tamper ${diff.path} at ${diff.line}:${diff.col} offset ${diff.offset})\n`,
      () => process.exit(0),
    );
  })
  .catch(fail);
