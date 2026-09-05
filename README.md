# recheck

`recheck` verifies an [EXHIBIT B](https://exhibitb.autofract.com) receipt on your own machine,
without contacting the issuer. It is a Go library, a command line (`recheck`, also published to
npm as `exhibitb`) and a WebAssembly module for the browser, all built from the same code.

The receipt format is [`spec/RECEIPT.md`](spec/RECEIPT.md); this repository is the reference
verifier for it, and the vectors in [`spec/vectors/`](spec/vectors/) are shared with the issuer's
implementation. Standard library only, MIT.

```
npx exhibitb verify receipt.json
```

## What a receipt proves, and what it does not

An EXHIBIT B receipt is an ed25519-signed, hash-chained record of a check the issuer ran over a
document: every citation in the document was resolved, fetched from more than one vantage point,
hashed and timestamped, and for each one the receipt says whether the source existed, whether it
could be read, and whether the quoted text was found in it. Every receipt carries this sentence,
and the schema refuses one without it:

> Attests what was checked, against which sources, at what time. Not a claim of truth.

A `PASS` from `recheck` establishes that:

- the file is byte-for-byte what the issuer sealed — `self_hash` recomputes over its canonical
  form (§1–§2 of the spec), so a changed character anywhere in the body is caught;
- the issuer's key signed exactly that hash, and the key is one this build pins (or one you
  passed in);
- the receipt has a definite place in the issuer's chain — `seq` and `prev_hash` — and, given the
  day's root file and an inclusion proof, sits inside a Merkle root the issuer published and
  cannot rewrite without contradicting itself;
- optionally, with `--refetch`, whether each cited URL still serves the bytes the receipt
  recorded.

It does not establish that a claim is correct, that a source is reliable, that a quote is fairly
used, or that the document cites everything it should. A receipt is evidence of *what was
checked*, nothing more; the disclaimer is in the file because the file is what gets forwarded.

Anyone can generate a key and sign a receipt-shaped file. `key_pinned` is the check that
separates the issuer's key from anyone else's: this build pins the issuer's production keys
(`keys/exhibitb.json`), and a receipt signed by any other key — the fixture key from the spec
vectors included — reports `key_pinned: warn` and `RESULT: INCOMPLETE`, never `PASS`.

## Install

- **npm** (Node 18 or newer): `npx exhibitb verify receipt.json`, or `npm i -g exhibitb` for a
  permanent `exhibitb` / `recheck` command. The package is the same verifier compiled to
  WebAssembly.
- **Binaries**: `recheck-linux-amd64`, `recheck-linux-arm64`, `recheck-darwin-arm64` and
  `recheck-windows-amd64.exe` are attached to each
  [release](https://github.com/20012001amiramir/recheck/releases).
- **Go**: `go install github.com/20012001amiramir/recheck/cmd/recheck@latest`
- **From source**: `make build` (Docker, no local Go needed) — see [Building](#building-and-testing).

## Quick start

`recheck verify receipt.json` checks a receipt you were given. The run below is reproducible from
this repository: it verifies the spec's own vector, which is signed by the fixture key, so that
key is passed in (`spec/vectors/receipt-valid.json` is written by `make wasm` — it is the
`receipt` member of `spec/vectors/receipt.json` as a file of its own).

```
$ recheck verify spec/vectors/receipt-valid.json --keys spec/vectors/test-key.json
✔ schema         receipt v1, kind exhibitb.receipt
✔ self_hash      1cb2f7a8834b8a9c120c593b88b407c7b83196cf7d6258519e3a7b8645e6bb3b
✔ signature      ed25519 by eb-receipt-test
✔ key_pinned     eb-receipt-test
✔ chain_fields   seq 1
receipt eb_2m4Kq8Xr7vTb3nHd · seq 1 · issued 2026-09-03T11:22:44Z · key eb-receipt-test
RESULT: PASS
```

One line per check, then the receipt's identity, then the result. Markers are `✔ ✘ ! –` on a
terminal and `+ - ! .` when the output is not a terminal or with `--ascii`. `-` in place of the
file reads standard input. Nothing on this path touches the network. Without `--keys`, the same
run ends in `! key_pinned` and `RESULT: INCOMPLETE` (exit 2): the fixture key is not pinned, and
a warning is as far as a receipt under an unpinned key can get.

## The offline guarantee, and how to check it

`recheck verify <file>` performs no network activity of any kind: no DNS, no connection, no
request. The two commands that do go online say so and never involve the issuer's servers in a
verification:

- `recheck verify <receipt id>` — an `eb_…` id in place of a file — fetches that receipt's public
  projection from the issuer (`https://exhibitb.autofract.com/api/receipt/<id>`), prints
  `fetching from issuer (online)` on stderr first, and then verifies it exactly as it would a
  file. `--offline` turns this into an error (exit 64); on a file `--offline` is accepted as a
  no-op, for scripts that want to state it.
- `--refetch` downloads each cited URL from *your* machine (15 s timeout, 5 MB cap, at most five
  redirects) and compares the sha256 of the raw bytes with the receipt's `content_sha256`. It
  refuses any URL whose host has `exhibitb` as one of its DNS labels — `exhibitb.autofract.com`,
  `api.exhibitb.autofract.com`, anything under them; not `exhibitb-roots.example` — on the first
  request and on every redirect. The verifier sends the issuer nothing about a re-check, and this
  guard keeps it that way when a cited URL or a redirect points at one of the issuer's hosts.

Do not take this file's word for it:

- Linux: `strace -f -e trace=network recheck verify receipt.json` shows no `socket`, `connect` or
  `sendto` calls.
- macOS: run `nettop` in another terminal while verifying; the process never appears. Or
  `sudo lsof -i -p $(pgrep recheck)` prints nothing.
- Browser: the demo on the issuer's landing page counts the requests the page makes; after
  `recheck.wasm` has loaded, the count does not move while you verify or edit a receipt.
- Source: the only `net/http` uses are in `refetch/` (the `--refetch` path and `fetch-hash`) and
  the `fetchFromIssuer` function in `cli/cli.go`; the page's WebAssembly module is built without
  either (`-tags nocli`) and does not link `net/http` at all.

## Commands

```
recheck verify <receipt.json | receipt id> [--proof proof.json] [--root roots/DATE.json] [--keys keys.json] [--refetch] [--json] [--offline]
recheck bind <receipt.json> <binding.json> <document>
recheck fetch-hash <url>
recheck show <receipt.json>            (prints the public projection)
recheck keygen [--out key.json]        (ed25519 keypair for counter-signing)
recheck countersign <receipt.json> --key key.json [--out receipt.signed.json]
recheck version
```

Flags go anywhere on the line, as `--flag value` or `--flag=value`. `--help` on any command prints
this list.

### `verify`

Runs the checks below on a receipt or on its public projection. `--keys keys.json` adds a key
set (the issuer's `/keys.json` shape, a bare array of entries, or one entry) to the compiled-in
one. `--root` and `--proof` together enable the inclusion checks: the root file for the receipt's
day (`GET /chain/root/<date>` at the issuer, also mirrored in the
[exhibitb-roots](https://github.com/20012001amiramir/exhibitb-roots) repository) and the proof
(`GET /api/receipt/<id>/proof`). One without the other is a warning, not a failure. `--refetch`
adds the re-fetch of every cited URL that has a recorded content hash.

| # | check | pass | fail | warn | skip |
|---|---|---|---|---|---|
| 1 | `schema` | strict receipt v1 (§4), else strict projection (§11) | not JSON, a duplicate key, a member missing, unknown or misshapen — `detail` names the path | — | — |
| 2 | `self_hash` | recomputed canonical hash equals the stated one | it does not | a projection: the sealed body is not present | schema failed |
| 3 | `signature` | exactly one `issuer` signature, by `issuer.key_id`, verifying under the embedded key | none, several, wrong key id, or it does not verify | — | schema failed |
| 4 | `key_pinned` | the pinned set has that key id with the same bytes | same id, different bytes; or a broken pin | key id not in the pinned set | no pinned set at all; schema failed |
| 5 | `chain_fields` | chained: `seq` ≥ 1 and hex `prev_hash` | chained without them, unchained with them | — | unchained receipt: not anchored to the public chain |
| 6 | `root_schema`, `root_self_hash`, `root_signature` | the root file parses, hashes and verifies under the pinned root key | it does not (an unpinned root key is a failure: the file carries no key) | — | with `--root` only |
| 7 | `inclusion` | the proof is for this receipt and rebuilds the root file's root | it is not, or does not | proof `pending`; `--root` or `--proof` missing | proof `unchained`; an earlier failure |
| 8 | `refetch` | every fetched source still carries the recorded bytes | — | a source changed or was unreachable | no URL with a content hash; a projection |

Exit codes:

| code | result | meaning |
|---|---|---|
| 0 | `PASS` | every check passed or was skipped (a skip is a check that does not apply) |
| 1 | `FAIL` | at least one check failed |
| 2 | `INCOMPLETE` | nothing failed, but something could not be established: an unpinned key, a changed or unreachable source, a proof without its root file, a pending proof |
| 64 | — | usage: a file that cannot be read, a key set that does not parse, an unknown flag, `--offline` with a receipt id |

A file that reads but is not a receipt is exit 1 with `first_failure.check = "schema"`, not 64.
A changed source under `--refetch` is a warning, not a failure: the receipt attests the bytes at
issue time, and the source having moved on is information, not a contradiction.

`--json` prints one object instead:

```json
{
  "ok": true,
  "exit": 0,
  "checks": [{ "name": "schema", "status": "pass", "detail": "receipt v1, kind exhibitb.receipt" }, "…"],
  "receipt": { "id": "eb_2m4Kq8Xr7vTb3nHd", "seq": 1, "issued_at": "2026-09-03T11:22:44Z", "key_id": "eb-receipt-2026-09", "kind": "exhibitb.receipt" },
  "first_failure": null,
  "refetch": [{ "n": 1, "status": "match", "url": "https://cdn.example.org/reports/2026/q1.pdf" }]
}
```

`first_failure` is `{check, detail}` for the first failing check; `refetch` entries have a
`status` of `match`, `changed` or `unreachable` and a `detail` when there is something to say;
`receipt` is filled in on a best-effort basis even when the schema fails. A run that could not
start (exit 64) answers `{ok: false, exit: 64, error: "…"}` with empty lists, so a caller never has
to parse stderr.

### `bind`

```
recheck bind receipt.json binding.json report.pdf
```

A receipt names the document only by hash, and each claim only by an HMAC, so that a receipt can
be public while the document stays private. `binding.json` is what the issuer hands the document's
owner: the binding key, and each claim's text and quote. `bind` recomputes the document's sha256
and every `claim_hmac` and `quote_hmac` (HMAC-SHA256 with the key, over `claim:` / `quote:` plus
the text normalised as the engine normalises it) and reports `document_sha256`, `binding_key` and
`claims` as pass or fail, with the same exit codes as `verify`. It is how the owner of a document
proves that *this* receipt is about *that* file.

### `fetch-hash`

```
recheck fetch-hash https://cdn.example.org/reports/2026/q1.pdf
sha256    a6c96f6533f8bcdb7549fd993b3e14a6af8c7ddf447d5535adde121a5936efde
bytes     812004
status    200
final_url https://cdn.example.org/reports/2026/q1.pdf
```

The same fetch `--refetch` does, for one URL, so a hash in a receipt can be compared by hand.
Exit 2 when the URL cannot be fetched; a host with `exhibitb` as one of its labels is refused, as
under `--refetch`.

### `show`

Prints the receipt's public projection (§11): the same file with every cited URL reduced to its
registrable domain and the archive links removed — what the issuer shows at `/r/<id>` — so you can
see exactly what is public about a receipt before forwarding it. A projection still verifies
(`self_hash` is a warning, since the body is not present), so it can be checked by someone who
was never given the receipt itself.

### `keygen` and `countersign`

Counter-signing is how a practice puts its own name on the receipts it hands out (the PRACTICE
tier of EXHIBIT B): a second signature, by a key the practice controls, over the same `self_hash`.

```
recheck keygen --out practice-key.json
recheck countersign receipt.json --key practice-key.json --out receipt.signed.json
recheck verify receipt.signed.json
```

`keygen` writes `{key_id, alg, public_key, private_pkcs8_b64, created_at}` (mode 0600, never
overwriting); `private_pkcs8_b64` is the secret half, and the other members are what to give
anyone who should check the counter-signature. `countersign` refuses a receipt that does not hash
to its `self_hash`, a projection, and a receipt that already carries eight signatures; the body
and the issuer's signature are untouched, so the receipt still verifies and still sits in the
chain where it was. `recheck verify` reports the issuer's signature; a counter-signature is
checked by whoever holds the counter-signer's public key — with this library, or any ed25519
tool: the message is the 32 raw bytes of `self_hash`, the signature is the `sig` member of the
`signatures` entry with `"role": "counter"`.

## Keys

`keys/exhibitb.json` is compiled into every build. It has the shape of the issuer's
`GET /keys.json`:

```json
{
  "keys": [
    { "key_id": "eb-receipt-2026-09", "alg": "ed25519", "purpose": "receipt", "public_key": "C9ANxVBj3NSUVEGOJ6FFrmVSlTrqCPjiDmEIoEmB8XI=", "created_at": "2026-09-04T22:23:18Z", "retired_at": null },
    { "key_id": "eb-root-2026-09",    "alg": "ed25519", "purpose": "root",    "public_key": "V2Pclq2fz2OA2f4Drs4O4C6Iv2eenqG2dSdxOnIGUqg=", "created_at": "2026-09-04T22:23:18Z", "retired_at": null }
  ]
}
```

Receipts are signed with a `receipt` key and root files with a `root` key. A key id names one
public key for all time — the issuer never reuses an id and never re-activates a retired key — so
a receipt sealed under a key that was later retired still verifies, and an entry whose bytes
differ from the receipt's embedded key is a failure, not a warning: it means someone signed under
the issuer's key id with a key of their own.

To pin a newer key set: fetch `https://exhibitb.autofract.com/keys.json`, compare it with what the
[exhibitb-roots](https://github.com/20012001amiramir/exhibitb-roots) repository publishes, replace
`keys/exhibitb.json` and rebuild — or pass the fetched file with `--keys` at run time. The fixture
keys under `spec/vectors/` (`eb-receipt-test`, `eb-root-test`) are never pinned: their private
halves are public by design, so that the vectors are reproducible by anyone.

## In the browser

`wasm/recheck.wasm` is the same verifier for a page; `wasm/recheck.js` loads it and
`wasm/wasm_exec.js` is the runtime shim of the toolchain that built it. The API is fixed:

```html
<script src="/wasm_exec.js"></script>
<script type="module">
  import { loadRecheck } from "/recheck.js";
  const recheck = await loadRecheck("/recheck.wasm");   // one fetch, this URL, nothing else

  recheck.version;                                        // "0.1.0"
  JSON.parse(recheck.verify(receiptText));               // the --json object above
  JSON.parse(recheck.verify(receiptText, { keys, root, proof }));   // each the text of that file
  JSON.parse(recheck.tamper(receiptText, editedText));   // see below
</script>
```

`verify` runs entirely in memory and makes no request; the module does not even link `net/http`.
`tamper(original, edited)` locates the first difference between two texts for the tamper
playground: `{changed, offset, line, col, path, whitespace_only, invalid_json}` — `offset` is
the first differing byte, `line`/`col` its position (1-based, `col` in UTF-16 units), `path` the
JSON pointer of the innermost value that changed when both texts parse (`/claims/3/says/verdict`),
`whitespace_only` when the canonical forms are equal (formatting moved, no hash notices), and
`invalid_json` when either text does not parse under the spec's rules. Serving notes: the page's
CSP needs `'wasm-unsafe-eval'` in `script-src`; serve the module as `application/wasm` and let the
server compress it.

`wasm/check.js` and `wasm/dump.js` exercise this API under Node (`./build.sh smoke` runs them):
`check.js` asserts the verdicts on the vectors, `dump.js` prints every verdict so two builds of
the module can be compared byte for byte.

### Toolchain and size

Two modules come out of `cmd/wasm`:

| module | contents | toolchain | size | gzip |
|---|---|---|---|---|
| `wasm/recheck.wasm` | `window.recheck` only (`-tags nocli`) | TinyGo 0.38.0, `-target wasm -no-debug` | 0.8 MB | 0.3 MB |
| `npm/wasm/recheck.wasm` | the same, plus the command line for the npm package | Go 1.23, `GOOS=js GOARCH=wasm -trimpath -ldflags "-s -w"` | 10.5 MB | 2.7 MB |

Each ships with the `wasm_exec.js` of the toolchain that built it (`$(tinygo env
TINYGOROOT)/targets/` and `$(go env GOROOT)/misc/wasm/`, `lib/wasm/` from Go 1.24 on); the two
shims are not interchangeable. `make smoke` runs every vector through both modules and insists on
byte-identical answers, so the page's module cannot drift from the one the Go tests cover.

Why two toolchains: TinyGo cannot build the npm module — its `net/http` has no
`Client.CheckRedirect`, which the issuer guard in `refetch` needs — and standard Go builds the
page's module at 3.9 MB (1.1 MB gzip), which is what `PAGE_TOOLCHAIN=go make wasm` gives you.
TinyGo 0.34.0, the release tried first, compiles the page's module but the result crashes on
start (a nil map inside its `syscall/js.FuncOf`; with `-opt=2`, an out-of-bounds access in
`regexp` during init); 0.38.0 is the first release that works. Measured here under Node, the
TinyGo module starts in a third of the time and verifies the vector receipt in about six
milliseconds against four.

## As a library

```go
import (
    "github.com/20012001amiramir/recheck/receipt"
    "github.com/20012001amiramir/recheck/verify"
)

keys, _ := receipt.Pinned()                       // the compiled-in set; merge --keys into it
rep := verify.Run(data, verify.Options{Keys: keys})
fmt.Println(rep.Exit, rep.FirstFailure)           // rep.JSON() is the --json output
```

| package | what it holds |
|---|---|
| `canonical` | the strict JSON parser and the canonical form of §1; `SelfHash` (§2) |
| `receipt` | receipt and projection schema (§4, §11), signatures (§3), key sets (§13), the five checks (§12), the projection |
| `chain` | genesis and link rules (§6–§7); `Replay` for an exported chain (JSONL) |
| `merkle` | the RFC 6962 tree (§8): roots, audit paths, inclusion |
| `root` | root files (§9) and proofs (§10) |
| `refetch` | fetch and hash a URL from this machine, with the limits and the issuer guard |
| `bind` | the `bind` command's checks and the engine's text normalisation |
| `tamper` | first differing byte, line:col, JSON pointer between two texts |
| `verify` | composes the checks into one report — what the CLI prints and the browser returns |
| `cli` | the command line, as a function of `(args, stdin, stdout, stderr) → exit code` |

## Building and testing

No toolchain is needed locally: `build.sh` runs every command in a container —
`golang:1.23-alpine` for Go, `tinygo/tinygo:0.38.0` for the page's module (Docker 27 was used).
With `GO_LOCAL=1` the same script uses the `go` and `tinygo` on your PATH, which is how CI runs
it.

```
make test        # go vet + go test ./...   (also vets cmd/wasm for js/wasm, both build variants)
make build       # native binary for this machine -> dist/recheck (dist/recheck.exe on Windows)
make release     # linux/amd64, linux/arm64, darwin/arm64, windows/amd64 -> dist/
make wasm        # wasm/recheck.wasm, npm/wasm/recheck.wasm, wasm_exec.js, spec/vectors/receipt-valid.json
make smoke       # the binary, the npm wrapper and the browser API against the vectors
make all         # test, build, wasm, smoke
```

The tests are offline and cover every vector: `canonical.json` and `selfhash.json`
(canonicalisation, including the cases that must be refused), `receipt.json` (the valid receipt,
its projection, an unchained receipt, and every tampered variant with the check it must fail),
`merkle.json` and `root.json` (trees, audit paths, a root file with its proofs), `test-key.json`
(the fixture key, used to reproduce the vector signatures byte for byte). `refetch` is tested
against a local `httptest` server, `bind` against a bundle built in the test, the CLI through its
`Main` function with every exit code. `make smoke` then runs the built binary and the npm wrapper
on `receipt-valid.json` (exit 0 with the fixture key, 2 without, 1 for a tampered copy),
`wasm/check.js` on the page's module, and `wasm/dump.js` on both modules, whose outputs must be
identical.

`VERSION=v0.1.0 make release` stamps a version; by default it is the tag on `HEAD`, else
`npm/package.json`'s version plus the short commit id. `GO_IMAGE` overrides the toolchain image.

## Spec and vectors

`spec/` is a verbatim copy of the issuer's `spec/` directory at commit `b40edd2` of the app
repository, and is updated by copying, never by editing here. Both implementations must pass every
vector; the vectors are the contract. If you find a receipt that one implementation accepts and the
other refuses, that is a bug in one of them, and an issue here is the right place for it.

## Licence

MIT — see [LICENSE](LICENSE).
