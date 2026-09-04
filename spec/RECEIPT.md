# EXHIBIT B receipt — format and verification, version 1

This document is the contract between the issuing server and every independent verifier. A
verifier written from this text alone, without reading the server's source, must reproduce every
byte the server hashes and signs. The vector files under `spec/vectors/` are the tests of that
claim; a verifier that passes all of them is conformant. Where this text and a vector disagree, the
vector is wrong and the text wins — but report it, because the two are generated from one code
path and should never disagree.

A receipt attests what was checked, against which sources, at what time. It never contains the
client's text: only hashes, spans, counts, times, verdicts and public locators. Every rule below
that restricts a string to a fixed shape exists to keep it that way.

Sections:

0. Conventions
1. Canonical form
2. Self-hash
3. Signature
4. Receipt v1
5. Unchained receipts
6. Genesis constant
7. Chain rules
8. Merkle tree
9. Root file v1
10. Inclusion proof
11. Public projection
12. Verifier checks and exit codes
13. Key pinning and `keys.json`
14. Vectors

## 0. Conventions

- **hex** — lowercase hexadecimal, two characters per byte. **hex64** — 64 lowercase hex
  characters: a 32-byte SHA-256 digest. Uppercase is never produced and never accepted.
- **sha256** — SHA-256 (FIPS 180-4) over exactly the bytes stated.
- **base64** — RFC 4648 §4, the standard alphabet `A–Z a–z 0–9 + /`, with `=` padding, no line
  breaks. The URL-safe alphabet is never produced and never accepted.
- **ed25519** — RFC 8032 "pure" Ed25519: no pre-hashing, no context string, 32-byte public keys,
  64-byte signatures. Signatures are deterministic, so signing the same bytes twice with the same
  key produces the same signature.
- **Strings** are sequences of UTF-16 code units, as in ECMAScript. Every length limit in this
  document counts UTF-16 code units — not bytes, not code points. `"😀"` has length 2.
- **Regular expressions** use ECMAScript syntax without the `u` flag, matching on UTF-16 code
  units. `\d` is `[0-9]`. `\s` is the ECMAScript white-space set: U+0009, U+000A, U+000B, U+000C,
  U+000D, U+0020, U+00A0, U+1680, U+2000–U+200A, U+2028, U+2029, U+202F, U+205F, U+3000, U+FEFF.
  An implementation whose engine defines `\s` as ASCII only (RE2, for one) must widen it to that
  set where a rule below uses `\s`.
- **Integer** — a JSON number whose mathematical value is a whole number with
  |n| ≤ 9007199254740991 (2^53 − 1). See §1.4 for why the textual form of the token does not
  matter and the value does.
- **Timestamp** — `YYYY-MM-DDTHH:MM:SSZ`, UTC, seconds precision, matching
  `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`. Never a fraction, never an offset. The reference
  implementation checks the shape only, not calendar validity.
- **Path notation** in error messages: `$` is the root, `$.key` a member, `$[3]` an element,
  composed as `$.claims[0].says.overlap_bp`.

## 1. Canonical form

The canonical form is RFC 8785 (JSON Canonicalization Scheme) restricted to the values a receipt
may contain. Every hash in this product is taken over canonical bytes, so two implementations must
produce the same bytes for the same value or nothing else in this document works.

### 1.1 Value model

A canonical value is one of: `null`, `true`, `false`, an integer (§0), a string, an array of
canonical values, or an object whose members are canonical values. Nothing else exists. A
serializer that meets anything else — a non-integer number, NaN, an infinity, an undefined value, a
function, a lone surrogate — fails with an error naming the path. The reference implementation
throws `CanonicalError` with messages of the form `non-integer number at $.claims[0].says.overlap_bp`,
`unpaired surrogate at $.a.b`, `unsupported value at $.u`.

### 1.2 Whitespace

None. No space, tab, newline or carriage return appears between tokens anywhere.

### 1.3 Literals

`null`, `true`, `false`, exactly those bytes.

### 1.4 Numbers

Only integers (§0) are representable. An integer is serialized as its decimal digits with a
leading `-` when negative: the grammar of the output token is `0` or `-?[1-9][0-9]*`. No `+`, no
leading zeros, no fraction, no exponent. Negative zero is serialized as `0`; the two zeroes cannot
produce different bytes. This is the ECMAScript `Number::toString` result for every safe integer,
which is what RFC 8785 §3.2.2.3 asks for, minus the non-integer cases that this profile forbids.

The rule is about values, not input tokens. A verifier reads JSON, then re-serializes
canonically; `812004`, `812004.0` and `8.12004e5` all read as the integer 812004 and all canonicalize
to `812004`, so a receipt that was pretty-printed or re-encoded by a well-behaved JSON library still
hashes to the same `self_hash`. What a verifier must refuse is any number whose value is not an
integer in range: `0.93`, `1e400`, `9007199254740992`. Such a value is a schema failure (§12), never a
different hash. An implementation that parses JSON numbers into IEEE-754 doubles gets this right
by construction: a double that is integral and within ±(2^53 − 1) is an integer, anything else is
refused. An implementation that parses into 64-bit integers must additionally refuse magnitudes
above 2^53 − 1, because the server never produces them and the reference verifier refuses them.

Scores are basis points (integers 0…10000) precisely so that no float is ever needed.

### 1.5 Strings

A string is serialized as `"`, then each UTF-16 code unit in order, then `"`. Code units are
escaped as follows and in no other way:

| code unit | output |
|---|---|
| U+0008 | `\b` |
| U+0009 | `\t` |
| U+000A | `\n` |
| U+000C | `\f` |
| U+000D | `\r` |
| U+0022 `"` | `\"` |
| U+005C `\` | `\\` |
| any other unit below U+0020 | `\u` followed by four lowercase hex digits: U+0000 → `\u0000`, U+001B → `\u001b`, U+001F → `\u001f` |
| everything else | the code unit itself, encoded as UTF-8 |

"Everything else" includes U+007F (DEL), U+0080 and above, U+2028 and U+2029, and all non-ASCII
text. A surrogate pair (a high surrogate U+D800–U+DBFF immediately followed by a low surrogate
U+DC00–U+DFFF) is emitted as the four-byte UTF-8 encoding of the code point it names. A lone
surrogate has no UTF-8 encoding and is an error, not an escape. `/` is never escaped. `\uXXXX` is
never used for a unit at or above U+0020, and the hex digits of a `\u` escape are always lowercase.

Object keys are serialized by the same rule.

### 1.6 Arrays

`[`, the elements serialized and joined by `,`, `]`. Order is preserved exactly as given; arrays
are never sorted. An empty array is `[]`.

### 1.7 Objects

`{`, the members serialized as `"key":value` and joined by `,`, `}`. An empty object is `{}`.

Members are sorted by key. Keys are compared as sequences of UTF-16 code units, unit by unit,
numerically; where one key is a prefix of another the shorter sorts first; the empty key sorts
first of all. This is RFC 8785 §3.2.3 and the default order of ECMAScript `Array.prototype.sort()`.
It is not code-point order and not byte order of the UTF-8 encoding: a key whose first code unit
is a high surrogate (U+D800–U+DBFF, the start of any character above U+FFFF) sorts *before* a key
starting with U+E000–U+FFFF. Concretely, for the four one-character keys U+FFFF, U+1F600 (`😀`, the
units U+D83D U+DE00), U+E000 and U+D7FF, the order is U+D7FF, U+1F600, U+E000, U+FFFF — the surrogate pair lands between U+D7FF and U+E000, where its first unit puts it, not after U+FFFF where its code point would. A JSON object cannot carry two
members with the same key; an implementation whose parser silently keeps the last duplicate
should refuse duplicates instead, since the server never emits them.

Sorting applies at every level of nesting, and to objects inside arrays. Arrays themselves keep
their order.

### 1.8 Output

The canonical bytes are the UTF-8 encoding of the string produced above, with no byte-order mark
and no trailing newline. Every hash in §2 is over these bytes.

### 1.9 Worked examples

From `spec/vectors/canonical.json`:

```
{}                                          → {}
{"b":1,"a":2,"C":3,"_":4}                   → {"C":3,"_":4,"a":2,"b":1}
{"ab":1,"a":2,"aa":3,"":4}                  → {"":4,"a":2,"aa":3,"ab":1}
{"é":1,"z":2,"A":3,"É":4}                   → {"A":3,"z":2,"É":4,"é":1}
{"c":"␀␁␟"}  (U+0000 U+0001 U+001F)      → {"c":"\u0000\u0001\u001f"}
{"zero":0,"one":1,"neg":-1}                 → {"neg":-1,"one":1,"zero":0}
{"a":[3,1,2,{"b":1,"a":2}]}                 → {"a":[3,1,2,{"a":2,"b":1}]}
```

## 2. Self-hash

```
self_hash(object) = hex( sha256( canonical( object minus its top-level members
                                             "self_hash" and "signatures" ) ) )
```

Only the two *top-level* members are removed; a member named `self_hash` nested anywhere deeper
is part of the hashed body. The rule is the same for a receipt (§4) and a root file (§9), and it is
why either can be signed, counter-signed or re-signed without its hash moving: the signatures live
outside the hashed body, and the hash lives outside itself.

Worked examples, from `spec/vectors/selfhash.json`:

```
{"a":1}   → sha256 of the bytes {"a":1}
          = 015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862
{}        → sha256 of the bytes {}
          = 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
```

and the fourth vector shows an object carrying a wrong `self_hash` and a nonsense `signatures`
array hashing to exactly what the same object hashes to without them.

## 3. Signature

- **Message.** The 32 raw bytes obtained by hex-decoding `self_hash`. Not the 64 hex characters,
  not the canonical JSON, not a hash of the hash. Ed25519 hashes its own input internally, so
  signing the digest directly is the whole scheme.
- **Algorithm.** Ed25519 (§0). The signature is 64 bytes.
- **Encoding.** base64 (§0) of the 64 bytes: always 88 characters matching
  `^[A-Za-z0-9+/]{86}==$`. A value that does not match this pattern is refused by the schema check
  before any cryptography runs.
- **Public keys.** The 32 raw Ed25519 public-key bytes in base64: always 44 characters matching
  `^[A-Za-z0-9+/]{43}=$`. This is the form used everywhere — inside receipts, in `keys.json`, in
  the vectors, in a pinned key set. It relates to the DER SubjectPublicKeyInfo encoding by a fixed
  12-byte prefix: `SPKI = 302a300506032b6570032100 ‖ raw32`, so either form converts to the other
  without an ASN.1 parser.
- **Verification.** Decode the public key (must be 32 bytes) and the signature (must be 64 bytes),
  decode `self_hash` (must be 32 bytes), run Ed25519 verify. Any decoding failure is a verification
  failure, never an error.
- **Signature entries.** A receipt's `signatures` array holds objects
  `{"key_id", "alg": "ed25519", "sig", "role"}` with `role` either `"issuer"` or `"counter"`. A root
  file's `signatures` array holds `{"key_id", "alg": "ed25519", "sig"}` — no `role`. In both, `sig`
  is over the containing document's `self_hash`.
- **The issuer signature** is the entry whose `role` is `"issuer"`. There is exactly one; its
  `key_id` must equal `issuer.key_id`; it is verified against `issuer.public_key` (§12, check 3)
  and that key is then compared with the pinned set (§12, check 4). A `"counter"` entry is a second
  party's signature added after issue; version 1 verifiers do not verify counter signatures and
  must not fail a receipt for carrying one.

## 4. Receipt v1

A receipt is a JSON object. The rules that hold for every object in it:

- **Strict.** Every member listed is required and no member not listed is allowed. An unknown
  member anywhere — top level, inside a claim, inside a retriever — is a schema failure.
- **Nullable means explicit.** A member marked `| null` is present and `null` when it has no
  value. Members are never omitted.
- **No free text.** Every string is an enum, a digest, base64, a URL with no whitespace, a
  timestamp, a lowercase token or a shape-checked identifier. A verifier enforces the shapes;
  the intent behind them is that a sentence from somebody's document cannot fit through any of
  them.
- Member order in the file is irrelevant; the canonical form (§1) sorts.

### 4.1 Primitive shapes

| name | rule |
|---|---|
| hex64 | `^[0-9a-f]{64}$` |
| timestamp | `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$` |
| http-url | length ≤ 2000 and `` ^https?:\/\/[^\s"'<>\\^`{\|}]+$ `` — absolute, `http` or `https`, no whitespace (§0's `\s`), and none of: double quote, single quote, `<`, `>`, backslash, caret, backtick, `{`, pipe, `}` |
| media-type | length ≤ 160 and `^[a-z0-9][a-z0-9!#$&^_.+-]{0,80}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,80}$` — a bare lowercase `type/subtype`, parameters stripped |
| extractor | length ≤ 40 and `^[a-z0-9]+(?:[.-][a-z0-9]+)*(?:@[0-9a-z.-]+)?$` — a tool name at a version, e.g. `unpdf@1`, `mammoth@1`, `paste` |
| model-id | `^[a-z0-9][a-z0-9._-]{1,63}$` |
| semver | `^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$` |
| key-id | `^eb-(?:receipt\|root)-[a-z0-9-]{1,20}$` (production keys are narrower, §13) |
| pubkey-b64 | `^[A-Za-z0-9+/]{43}=$` |
| sig-b64 | `^[A-Za-z0-9+/]{86}==$` |
| token(N) | length ≤ N and `^[a-z][a-z0-9_]*$` — a lowercase machine word, never a sentence |
| bp | integer 0 ≤ n ≤ 10000 (basis points) |
| span | a two-element array `[start, end]` of integers ≥ 0; the reference implementation does not check `start ≤ end` |
| receipt-id | `^eb_[abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789]{16}$` — `eb_` plus 16 characters from a 56-symbol alphabet with no `0 O 1 l I` |
| date | `^\d{4}-\d{2}-\d{2}$` |

### 4.2 Top level

| member | type | rule |
|---|---|---|
| `v` | integer | the literal `1` |
| `kind` | string | `"exhibitb.receipt"` (chained) or `"exhibitb.receipt.unchained"` (§5) |
| `id` | receipt-id | |
| `seq` | integer ≥ 1 \| null | position in the chain; `null` exactly when unchained |
| `prev_hash` | hex64 \| null | `self_hash` of the receipt at `seq − 1`, or the genesis constant (§6) at `seq` 1; `null` exactly when unchained |
| `issued_at` | timestamp | the moment of sealing |
| `issuer` | object | §4.3 |
| `scope_disclaimer` | string | the literal `Attests what was checked, against which sources, at what time. Not a claim of truth.` |
| `document` | object | §4.4 |
| `binding` | object | §4.5 |
| `claims` | array of claim, ≤ 1000 | §4.6, in document order |
| `counts` | object | §4.9 |
| `models` | array of model, ≤ 16 | §4.10 |
| `engine` | object | §4.11 |
| `self_hash` | hex64 | §2 |
| `signatures` | array of signature, ≤ 8 | §3; empty only between build and sign, never in an issued receipt |

### 4.3 `issuer`

| member | rule |
|---|---|
| `name` | the literal `"EXHIBIT B"` |
| `url` | http-url — the issuing site |
| `key_id` | key-id — the receipt key this receipt is signed under |
| `public_key` | pubkey-b64 — that key's public half, embedded so a receipt is self-describing; §12 check 4 decides whether to believe it |

### 4.4 `document`

| member | rule |
|---|---|
| `sha256` | hex64 — SHA-256 of the uploaded bytes |
| `bytes` | integer ≥ 0 — their length |
| `media_type` | media-type |
| `text_sha256` | hex64 — SHA-256 of the extracted text, as the engine hashed it; opaque to a verifier |
| `chars` | integer ≥ 0 — length of that text |
| `extractor` | extractor |

### 4.5 `binding`

| member | rule |
|---|---|
| `alg` | the literal `"HMAC-SHA256"` |
| `key_sha256` | hex64 — SHA-256 of the binding key |

The binding key is a per-receipt secret handed only to the creator. `claim_hmac`, `quote_hmac`
and the `value` of an `unsupported` locator are HMAC-SHA256 digests under it, so the holder of the
key can re-derive them from their own document and nobody else can read anything out of them. A
verifier treats all of them as opaque hex64 values.

### 4.6 A claim

| member | rule |
|---|---|
| `n` | integer ≥ 1 — 1-based position |
| `claim_hmac` | hex64 |
| `quote_hmac` | hex64 \| null |
| `doc_span` | span — where the claim sits in the extracted text |
| `locator` | object, §4.7 |
| `level` | `"EXISTS"` or `"SAYS"` — how far the check went |
| `exists` | object, §4.8.1 |
| `says` | object, §4.8.2 |
| `refutation_attempted` | boolean |
| `dissent` | the literal `null` — always; an adversarial second opinion never reaches a sealed receipt |

### 4.7 `locator`

Discriminated on `type`:

| `type` | `value` | `url` |
|---|---|---|
| `"url"` | http-url | http-url \| null |
| `"doi"` | length ≤ 200 and `^10\.\d{4,9}\/\S+$` | http-url \| null |
| `"pmid"` | `^\d{1,9}$` | http-url \| null |
| `"case"` | length ≤ 80 and `^(?:\d{1,4}\|\[\d{4}\])\s[A-Za-z0-9.'&\- ]{1,60}\s\d{1,6}$` — volume (or bracketed year), reporter, page: `410 U.S. 113`, `[2019] EWHC 12`, `2019 SCC 5` | http-url \| null |
| `"unsupported"` | hex64 — the HMAC of the citation string (§4.5), because the string itself would be the claimant's own text | the literal `null` |

### 4.8 Verdicts

#### 4.8.1 `exists`

| member | rule |
|---|---|
| `verdict` | one of the five below |
| `final_url` | http-url \| null — where the source was finally read from, after redirects |
| `http_status` | integer 0…599 \| null |
| `fetched_at` | timestamp \| null |
| `content_type` | media-type \| null |
| `bytes` | integer ≥ 0 \| null |
| `content_sha256` | hex64 \| null — SHA-256 of the fetched bytes |
| `text_sha256` | hex64 \| null — SHA-256 of the text extracted from them |
| `retrievers` | array ≤ 8 of retriever objects, each with `id` matching `^[A-Za-z0-9_-]{1,16}$`, `vantage` matching `^[a-z][a-z0-9_-]{0,23}$`, `status` an integer 0…599 or the literal `"unavailable"`, and `content_sha256` hex64 \| null |
| `retriever_disagreement` | boolean — two retrievers fetched different bytes |
| `single_retriever` | boolean — only one vantage answered |
| `registry` | `{ agency: token(32), status: integer 0…999 }` \| null — the registry consulted for a doi/pmid/case locator and what it answered |
| `archive_url` | http-url \| null |
| `archive_status` | `"archived"`, `"requested"`, `"failed"` or `"skipped"` |
| `archive_job_id` | `^[A-Za-z0-9_.:-]{1,80}$` \| null |

`verdict` values:

| value | meaning |
|---|---|
| `RESOLVED` | the source was reached and its content read |
| `RESOLVED_NO_ACCESS` | the source exists and answered, but its content could not be read (paywall, login, 403) |
| `NOT_FOUND` | the registry says the identifier does not exist — a DOI the resolver 404s, a PMID absent from the index, a citation lookup that 404s |
| `SOURCE_UNREACHABLE` | the network did not answer, or answered 5xx: nothing is known about the source either way |
| `UNSUPPORTED_LOCATOR` | the citation is of a kind the engine cannot resolve; its locator is `unsupported` |

`NOT_FOUND` and `SOURCE_UNREACHABLE` are different facts about different parties and are never
merged.

#### 4.8.2 `says`

| member | rule |
|---|---|
| `verdict` | `"MATCH"`, `"DRIFT"`, `"NOT_FOUND"` or `"NOT_RUN"` |
| `reason` | token(48) \| null — why, when `NOT_RUN` (for example `no_source_text`, `unsupported_locator`); not a closed list in version 1 |
| `quoted_span` | span \| null — where in the source text the match was found |
| `match_kind` | `"exact"`, `"overlap"` or null |
| `overlap_bp` | bp \| null — how much of the quote the source carries, in basis points |

`MATCH` means the quote was found at or above `engine.says_thresholds.match_bp`; `DRIFT` means
it was found between `drift_min_bp` and `match_bp`; `NOT_FOUND` means nothing at or above
`drift_min_bp`; `NOT_RUN` means the SAYS check did not run, and `reason` says why.

### 4.9 `counts`

Ten integers ≥ 0: `claims`, `resolved`, `no_access`, `unreachable`, `unsupported`, `says_match`,
`says_drift`, `says_not_found`, `says_not_run`, `holds_attempted`. They are the issuer's tallies
over `claims` and are informational: a verifier does not cross-check them against the claims in
version 1 (they are inside the hashed body, so they cannot be altered without failing
`self_hash`). Note that there is no `not_found` tally for the `NOT_FOUND` exists verdict; the four
exists tallies do not necessarily sum to `claims`.

### 4.10 `models`

Each entry is `{ role: token(24), model: model-id }`.

### 4.11 `engine`

| member | rule |
|---|---|
| `name` | the literal `"exhibitb"` |
| `version` | semver |
| `normalize` | the literal `"norm@1"` — the text normalization the HMACs and spans were computed under |
| `says_thresholds` | `{ match_bp: bp, drift_min_bp: bp }` — currently `10000` and `7500` |

### 4.12 A signature

`{ key_id: key-id, alg: "ed25519", sig: sig-b64, role: "issuer" | "counter" }` — see §3.

## 5. Unchained receipts

An unchained receipt has `kind` `"exhibitb.receipt.unchained"`, `seq` `null` and `prev_hash`
`null`. Everything else is identical to a chained receipt: same body, same `self_hash` rule, same
issuer signature. It has no place in the chain, is never a leaf of any Merkle tree, and has no
inclusion proof — `GET /api/receipt/<id>/proof` answers `200 {"status":"unchained","roots_at":null}`.
Nothing about it is retained past its own record.

For a verifier the only difference is check 5 (§12): `chain_fields` is `skip` when `seq` and
`prev_hash` are both `null`, and `fail` if an unchained receipt carries either. The mirror rule
holds for `"exhibitb.receipt"`: both must be present.

## 6. Genesis constant

The first receipt in the chain points at a constant nobody controls:

```
GENESIS_HASH = sha256("exhibitb.genesis.v1")
             = 3058620acf7ca95f8cc2c8970e7fc04afdbdeab9e688603bdd2e03a3bfcb588f
```

The input is the 19 ASCII bytes of `exhibitb.genesis.v1`, with no newline. The value is compiled
into the verifier as a literal. It is the `prev_hash` of the receipt at `seq` 1, the `prev_root` of
the first daily root file (§9), and what `GET /chain/head` reports as `self_hash` while the chain
is still empty.

## 7. Chain rules

1. There is one chain per issuer. `seq` is dense and starts at 1: the n-th chained receipt ever
   issued has `seq` n.
2. `prev_hash` of `seq` 1 is the genesis constant. `prev_hash` of `seq` n > 1 is the `self_hash`
   of `seq` n − 1.
3. Both `seq` and `prev_hash` are inside the hashed, signed body, so a receipt's position is
   signed with it. Moving a receipt, or changing what came before it, changes its `self_hash`.
4. `issued_at` is the sealing time. Receipts are ordered by `seq`, not by time; a verifier does not
   require `issued_at` to be monotonic.
5. Appending is atomic on the server: the chain row and the receipt record are written in one
   transaction, so `seq` can never be minted twice.

A verifier holding two receipts at `seq` n and n + 1 may check `receipt[n+1].prev_hash ==
receipt[n].self_hash`; this is not one of the numbered checks in §12 because a single receipt
cannot be checked that way.

### 7.1 What the issuer publishes about the chain

`GET /chain/head` — `{"seq", "self_hash", "issued_at", "last_root"}`. `seq` is 0, `self_hash` the
genesis constant and `issued_at` `null` on an empty chain. `last_root` is
`{"date", "root", "prev_root", "count", "first_seq", "last_seq"}` for the most recent root file, or
`null`.

`GET /chain/verify` — the server's own replay from genesis:
`{"ok", "checked", "head_seq", "head_hash", "first_broken", "verified_at", "ms"}` where
`first_broken` is `null` or `{"seq", "reason"}` with `reason` one of `prev_hash` (the link at that
`seq` does not point at the receipt before it), `self_hash` (the stored receipt no longer hashes to
its recorded `self_hash`), `signature` (the issuer signature does not verify under the key
published for its `key_id`, or the embedded key differs from the published one), `root` (a rooted
day's receipts no longer hash to the stored root; `seq` is that root's `last_seq`, or 0 for an empty
day). The server verifies signatures against the keys it has published for the `key_id`, never
against the key embedded in the receipt, so a receipt cannot vouch for itself. The answer is cached
for sixty seconds.

Both answer JSON with `cache-control: no-store`.

## 8. Merkle tree

Each UTC day's chained receipts form one Merkle tree, hashed exactly as RFC 6962 §2.1 (and RFC
9162 §2.1.1, which is the same function):

- The **leaves** are the day's chained receipts in `seq` order. A day is the UTC calendar date of
  `issued_at` — its first ten characters. Unchained receipts are never leaves.
- The **leaf data** for a receipt is the 32 raw bytes of its `self_hash` (hex-decoded).
- `MTH({})` — the empty tree — is `sha256` of the empty string:
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- `MTH({d0})` = `sha256(0x00 ‖ d0)`: one byte `0x00`, then the 32 leaf bytes.
- For n > 1, `MTH(D[n])` = `sha256(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n]))` where k is the largest
  power of two strictly less than n (n = 2 → 1, 3 → 2, 4 → 2, 5 → 4, 7 → 4, 8 → 4, 9 → 8), and
  `D[0:k]` is the first k leaves. One byte `0x01`, then the two 32-byte subtree hashes.
- The **root** is `MTH` of the whole day, as hex64.

The `0x00`/`0x01` prefixes are what stop a leaf from being passed off as an interior node. Note
that a one-leaf tree's root is the leaf *hash* `sha256(0x00 ‖ d0)`, not the leaf data.

`spec/vectors/merkle.json` gives the roots for trees of 0, 1, 2, 3 and 7 leaves, with every audit
path. For the size-1 tree, whose leaf is `sha256("exhibitb.vector.leaf.0")`, the root is
`a5b314a22917a23286ed9706710de30e2267f9ced15b5e57957493b858919ce0`.

## 9. Root file v1

One signed file per UTC day, committing that day's tree and linking it to the day before. It is
canonical JSON (§1) with `self_hash` per §2 and a signature per §3 under the issuer's *root* key
(a different key from the receipt key).

| member | rule |
|---|---|
| `v` | the literal `1` |
| `kind` | the literal `"exhibitb.root"` |
| `date` | date — the UTC day |
| `first_seq` | integer ≥ 1 \| null — `seq` of the day's first leaf; `null` on an empty day |
| `last_seq` | integer ≥ 1 \| null — `seq` of its last leaf; `null` on an empty day |
| `count` | integer ≥ 0 — number of leaves |
| `root` | hex64 — `MTH` of the day (§8); the empty-tree value on an empty day |
| `prev_root` | hex64 — `root` of the most recent earlier root file, or the genesis constant for the first file ever |
| `head_hash` | hex64 — `self_hash` of the chain head at the moment the file was cut, which may belong to a later day than `date` |
| `key_id` | key-id — the root key |
| `self_hash` | hex64 — §2 |
| `signatures` | array ≤ 8 of `{ key_id: key-id, alg: "ed25519", sig: sig-b64 }` — no `role`; the first entry is the issuer's |

Rules:

1. A root file is cut at or after 00:05 UTC on the day after `date`, once per day, in date order,
   so `prev_root` links every file to the one before it back to genesis. An empty day still gets a
   file: a gap in the series would be indistinguishable from a day somebody removed.
2. Once stored a root file is never rewritten. A receipt that lands in an already-rooted day is
   not in that day's tree; its proof stays pending (§10).
3. The file is published to a public repository as `roots/<date>.json`, and again as
   `roots/latest.json`, each containing the canonical bytes followed by one `\n`. The issuer also
   serves it at `GET /chain/root/<date>` as the canonical bytes with no trailing newline (404 until
   the day is rooted). Strip a trailing newline before hashing; better, parse and re-canonicalize.
4. To verify a root file: parse; schema as above; `self_hash` recomputed per §2 must equal the
   stated one; the first signature's `key_id` must equal `key_id`, and its `sig` must verify under
   the pinned public key for that `key_id` (§13) — the file does not embed the key, so an unpinned
   root key means the signature cannot be checked. Across consecutive files, each `prev_root` must
   equal the previous `root`.

The root file in `spec/vectors/root.json` covers three receipts of 2026-09-03 and hashes to
`8a45d351ed3c006ec3dbcf01766b235385c8acec918e5756e369e8afbdaa1225`; its `root` is
`738cd1fea57ceff0535739f56ed3d879bd352bd78ce027165164813474cbf2ee`.

## 10. Inclusion proof

`GET /api/receipt/<id>/proof` answers, once the receipt's day is rooted:

```
{
  "receipt_id": "eb_…",
  "self_hash":  hex64,          the receipt's, which is the leaf data
  "seq":        integer,
  "date":       date,           the UTC day, hence which root file
  "leaf_index": integer ≥ 0,    0-based position among the day's leaves
  "tree_size":  integer ≥ 1,    the day's leaf count, equal to the root file's count
  "root":       hex64,          the root file's root
  "audit_path": [hex64, …],     RFC 6962 §2.1.1 PATH(leaf_index, D[tree_size])
  "root_file":  "roots/<date>.json"
}
```

Before the day is rooted the answer is `202 {"status":"pending","roots_at":"<timestamp>"}` where
`roots_at` is the next 00:05 UTC. An unchained receipt answers `200 {"status":"unchained","roots_at":null}`.
An unknown id is 404. The server withholds a proof (answers pending) if the day's leaves no longer
hash to the stored root, so a served proof always points at a tree that was signed.

`audit_path` is ordered from the leaf upward: the first entry is the hash of the leaf's sibling
subtree, the last is the hash of the largest subtree not containing the leaf. Its length is 0 for
a one-leaf tree. In RFC 6962's recursion: `PATH(m, {d0}) = {}`; for n > 1 with k as in §8,
`PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n])` if m < k, else `PATH(m − k, D[k:n]) : MTH(D[0:k])`.

To verify, rebuild the root from the leaf and the path (RFC 9162 §2.1.3.2):

```
fn = leaf_index; sn = tree_size − 1
r  = sha256(0x00 ‖ leaf_bytes)
for each p in audit_path:
    if sn == 0: FAIL                         (more path than the tree can have)
    if fn is odd, or fn == sn:
        r = sha256(0x01 ‖ p ‖ r)
        while fn != 0 and fn is even: fn >>= 1; sn >>= 1
    else:
        r = sha256(0x01 ‖ r ‖ p)
    fn >>= 1; sn >>= 1
PASS iff sn == 0 and r == root
```

Refuse before starting if `leaf_index < 0`, `tree_size < 1`, `leaf_index ≥ tree_size`, or any
value is not hex64. A proof presented at the wrong `leaf_index` rebuilds a different root and
fails; a `tree_size` the path cannot belong to leaves `sn ≠ 0` and fails.

A complete inclusion check therefore establishes, in order: the receipt verifies (§12); the root
file for `date` verifies (§9 rule 4); `proof.root == root_file.root` and `proof.tree_size ==
root_file.count`; `proof.self_hash == receipt.self_hash`; and the rebuilt root equals `root`. Then
the receipt was among that day's leaves when the issuer signed the day.

`spec/vectors/root.json` carries one proof per receipt of its three-leaf tree.

## 11. Public projection

The receipt page and `GET /api/receipt/<id>` show a **projection**: the receipt with every cited
URL removed. The full receipt with its URLs is the creator's to download (that endpoint answers
`403 {"error":"creator_only"}` to anyone else). The projection rule:

- Each `claims[i].locator` becomes `{"type", "domain"}` — the same `type`; `value` and `url` are
  gone.
- Each `claims[i].exists` loses `final_url` and `archive_url`. Every other member stays, including
  `http_status`, hashes, `retrievers`, `registry`, `archive_status` and `archive_job_id`.
- Everything else is byte-for-byte the receipt: `id`, `seq`, `prev_hash`, `issued_at`, `issuer`,
  `document`, `binding`, `counts`, `models`, `engine`, **`self_hash` and `signatures`**. A
  projection carries the *receipt's* hash and signatures; it is a view of a receipt, not a document
  that hashes to itself.

`domain` (`^[a-z0-9][a-z0-9._-]*$`, length ≤ 253, or `null`):

- `type` `"url"`: the registrable host of `exists.final_url` when it is not `null`, else of
  `locator.value`.
- `type` `"doi"`, `"pmid"`, `"case"`: `exists.registry.agency`, or `null` when `registry` is `null`.
- `type` `"unsupported"`: `null`.

Registrable host of a URL: parse it; take the hostname, lowercased; drop a leading `www.`; if it
is an IPv4 literal or contains `:`, keep it whole; if it has two labels or fewer, keep it whole;
otherwise keep the last two labels — or the last three when the last two are one of `ac.jp`,
`ac.uk`, `co.in`, `co.jp`, `co.nz`, `co.uk`, `co.za`, `com.au`, `com.br`, `edu.au`, `gov.au`,
`gov.uk`, `net.au`, `org.au`, `org.uk`. Unparseable → `null`. So
`https://www.example.org/reports/q1.pdf` → `example.org`, `https://pubmed.ncbi.nlm.nih.gov/31234567/`
→ `nih.gov`, `https://www.bmj.co.uk/content/1` → `bmj.co.uk`. A verifier never needs to compute
this; it is listed so the projection is fully specified.

A verifier given a projection instead of a receipt (the JSON the public page serves) runs the
same checks: check 1 recognises the projection shape, check 2 is `warn` because the body needed
to recompute `self_hash` is not present, checks 3–5 run normally against the stated `self_hash`.
The best such a run can conclude is that the issuer signed the stated hash — exit code 2, not 0.

## 12. Verifier checks and exit codes

Input: one JSON document — a receipt or a projection — read from a file or standard input. Any
JSON whitespace or member order is fine; the verifier re-canonicalizes. Optional inputs: a pinned
key set (§13; the release build carries one), a root file and a proof (§10).

The checks, in this order, each with a `name`, a `status` of `pass`, `fail`, `warn` or `skip`, and
a free-form `detail`:

| # | name | pass | fail | warn | skip |
|---|---|---|---|---|---|
| 1 | `schema` | parses and matches §4 (receipt) or §11 (projection) exactly | anything else — not JSON, unknown member, wrong shape, non-integer number, wrong literal; `detail` names the first offending path | — | — |
| 2 | `self_hash` | §2 recomputed over the receipt equals its `self_hash` | it does not | input is a projection: the body is not present, nothing recomputed | schema failed |
| 3 | `signature` | the `"issuer"` entry's `sig` verifies under `issuer.public_key` over `self_hash` | no `"issuer"` entry; its `key_id` ≠ `issuer.key_id`; or the signature does not verify | — | schema failed |
| 4 | `key_pinned` | the pinned set has `issuer.key_id` with the same `public_key` | the pinned set has `issuer.key_id` with a *different* `public_key` — someone signed under the issuer's key id with a key of their own | `issuer.key_id` is not in the pinned set — perhaps a key newer than this verifier | no pinned set was supplied; schema failed |
| 5 | `chain_fields` | kind `"exhibitb.receipt"` with integer `seq` ≥ 1 and hex64 `prev_hash` | a chained receipt missing either; an unchained one carrying either | — | kind `"exhibitb.receipt.unchained"` with both `null`; schema failed |

After a `schema` failure checks 2–5 are all reported as `skip`. Every check runs regardless of
earlier failures otherwise, so the report is complete; `first_failure` is the name of the first
check whose status is `fail`, or `null`. `ok` is true when no check failed. A `warn` never makes
`ok` false.

Check 3 verifies against the key *embedded* in the receipt on purpose: it establishes that the
document is internally consistent, and check 4 then establishes whether that key is the issuer's.
Reporting them separately is what lets a verifier say "well-formed and signed, but not by a key I
know" rather than merely "bad".

When a proof and root file are supplied, the verifier additionally reports `root_schema`,
`root_self_hash`, `root_signature` (under the pinned root key for the file's `key_id`; `fail` when
that key is not pinned, since the file carries no key), and `inclusion` (§10, including the
`root`/`count`/`self_hash` cross-checks), with the same statuses. A proof endpoint answering
`pending` is reported as `inclusion` `warn`.

Exit codes:

| code | meaning |
|---|---|
| 0 | every check is `pass` or `skip` |
| 1 | at least one check is `fail` |
| 2 | no check failed, but at least one is `warn`: the verifier could not establish everything — a projection's hash was not recomputed, a key is not pinned, a proof is still pending |
| 64 | usage: unrecognised flags, a missing or unreadable input file. A file that reads but is not a receipt is exit 1 with `first_failure` `schema`, not 64 |

Machine output, when requested, is `{"ok", "checks": [{"name", "status", "detail"}], "first_failure"}`
with the checks in the order above. `detail` strings are for people and are not part of this
contract.

## 13. Key pinning and `keys.json`

The issuer publishes every key it has ever signed with at `<issuer url>/keys.json`
(`cache-control: public, max-age=300`):

```
{
  "keys": [
    {
      "key_id":     "eb-receipt-2026-09",
      "alg":        "ed25519",
      "purpose":    "receipt",          or "root"
      "public_key": pubkey-b64,
      "created_at": timestamp,
      "retired_at": timestamp | null
    },
    …
  ]
}
```

- Entries are ordered by `created_at`, then `key_id`. Retired keys stay listed forever: a receipt
  sealed under a key that was later retired still verifies, and `retired_at` says when the issuer
  stopped using it. A verifier treats both timestamps as informational.
- **Key ids** in production are `eb-<purpose>-<YYYY-MM>` — `eb-receipt-2026-09`,
  `eb-root-2026-09` — named for the month the key was made. One key id names one public key for
  all time; the issuer refuses to publish a second key under an existing id. The receipt schema
  (§4.1) accepts the wider `^eb-(?:receipt|root)-[a-z0-9-]{1,20}$` so that the fixture keys below
  fit through it.
- **Purposes.** Receipts are signed with a `receipt` key, root files with a `root` key. A pinned
  set is therefore two lists; check 4 consults the `receipt` list, root verification the `root`
  list.
- **Pinning.** A release of the verifier compiles in the `{key_id, public_key}` pairs from
  `keys.json` at build time. Check 4 compares the receipt's embedded key against that set: same
  key → `pass`; unknown id → `warn` (the receipt may be newer than the verifier: refresh the pinned
  set, or pass a freshly fetched `keys.json`); known id, different key → `fail`. A verifier may
  accept a `keys.json` file on the command line in place of, or in addition to, its compiled set.
- **Fixture keys.** `spec/vectors/test-key.json` is `{"key_id": "eb-receipt-test",
  "private_pkcs8_b64", "public_key"}` — a committed Ed25519 key whose private half is public by
  design, so the vectors are reproducible. Its public key is
  `+OIf8AWG2M/e4fqmltCC+xtj9kmks5fAk3UjznkHRuQ=`. The root vector signs with the same key pair
  under the id `eb-root-test`. The issuer refuses to sign anything real with an id outside
  `^eb-(?:receipt|root)-\d{4}-\d{2}$`, and a release verifier must not carry either fixture id in
  its pinned set; pin them only when running the vectors.
- **Private keys** never leave the issuer. Public keys are the only thing a verifier ever holds.

## 14. Vectors

All files are under `spec/vectors/`, generated by one deterministic script from the reference
implementation, so re-running it produces byte-identical files. They are pretty-printed JSON; the
canonical bytes a case is about are carried as string values inside them, never as the file's own
layout. Read each file with an ordinary JSON parser.

### `canonical.json`

An array of `{"name", "input", "canonical"}`. For each case, canonicalize `input` (§1) and compare
the UTF-8 bytes with `canonical` (a string; encode it as UTF-8). Fifteen cases: empty object and
array; literals; key order for ASCII, prefixes, non-ASCII and the surrogate-pair edge; every
escape; control characters; U+007F and U+0080 literal; non-ASCII pass-through; integers including
0, negatives and ±(2^53 − 1); array order; nested sorting; a receipt-shaped fragment. Also check
that parsing `canonical` and canonicalizing again returns the same bytes.

### `selfhash.json`

An array of `{"name", "input", "self_hash"}`. For each, `self_hash(input)` (§2) must equal
`self_hash`. The fourth case carries a bogus `self_hash` and `signatures` that must be ignored.

### `merkle.json`

An array of `{"tree_size", "leaves", "root", "proofs"}` for sizes 0, 1, 2, 3 and 7. `leaves` are
hex64 leaf data (`sha256("exhibitb.vector.leaf.<i>")`); `root` is `MTH` over them (§8); `proofs`
holds one `{"leaf_index", "tree_size", "audit_path"}` per leaf. Check that the root matches, that
each audit path is what §10's `PATH` produces, and that each proof verifies against the root by the
§10 algorithm. The size-0 entry has an empty `leaves`, the empty-tree root and no proofs.

### `receipt.json`

```
{
  "note":             string,
  "key":              {"key_id": "eb-receipt-test", "public_key"},   the pinned set to use
  "receipt":          a sealed chained receipt (seq 1, prev_hash = genesis),
  "self_hash":        its self_hash,
  "canonical_sha256": sha256 of its full canonical bytes, self_hash and signatures included,
  "projection":       its public projection (§11),
  "unchained":        {"receipt", "self_hash"} — the same body issued unchained,
  "tampered":         [{"name", "first_failure", "receipt"}, ×3]
}
```

With `key` as the pinned set: `receipt` must pass all five checks (exit 0);
`self_hash(receipt)` must equal `self_hash`, which is
`1f4a2ef76a73b189d25ef661e863c4bfb9d5bb5bcdc94ceee8b19d97af1d9ed5`; `sha256(canonical(receipt))`
must equal `canonical_sha256` (`9835aeb30839af44ebe27ca4f103a175c928b623ce2a61c4b7d1bf7f518ac269`)
— the integrity check for a downloaded file, distinct from the hash that is signed. `projection`
must pass with `self_hash` `warn` and everything else `pass` (exit 2). `unchained.receipt` must
pass with `chain_fields` `skip` and hash to `unchained.self_hash`. Each `tampered[i].receipt` must
have `ok` false and `first_failure` equal to `tampered[i].first_failure`: an edited `overlap_bp`
→ `self_hash`; one flipped signature byte → `signature`; an unknown `kind` → `schema` (with checks
2–5 `skip`).

### `root.json`

```
{
  "note":                string,
  "key":                 {"key_id": "eb-root-test", "public_key"},   the pinned root key
  "receipts":            [{"id", "seq", "issued_at", "prev_hash", "self_hash"}, ×3],
  "root_file":           the signed root file for 2026-09-03 (§9),
  "root_file_canonical": its canonical bytes as a string,
  "proofs":              [{"receipt_id", "self_hash", "leaf_index", "tree_size",
                           "audit_path", "root", "root_file"}, ×3]
}
```

Check that the three receipts chain from genesis (`receipts[0].prev_hash` is the genesis constant,
each later `prev_hash` is the previous `self_hash`); that `canonical(root_file)` equals
`root_file_canonical`; that `self_hash(root_file)` equals its `self_hash`; that its signature
verifies under `key`; that `root_file.root` equals `MTH` over the three `self_hash` values; that
`prev_root` is the genesis constant; and that every proof verifies against `root_file.root` by
§10. Any receipt from `receipt.json`'s body sealed at those ids and times reproduces these values
exactly.

### `test-key.json`

`{"key_id": "eb-receipt-test", "private_pkcs8_b64", "public_key"}`. `private_pkcs8_b64` is the
base64 of the DER PKCS#8 PrivateKeyInfo of the fixture key; `public_key` its raw public half in
the §3 form. A verifier needs only `public_key`; the private half is there so that the vectors can
be regenerated and so that another implementation can produce signatures to compare against
`receipt.json` and `root.json` — Ed25519 is deterministic, so they must be byte-identical.
