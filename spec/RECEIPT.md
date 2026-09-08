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
15. Compatibility
16. Known design notes

## 0. Conventions

- **hex** — lowercase hexadecimal, two characters per byte. **hex64** — 64 lowercase hex
  characters: a 32-byte SHA-256 digest. Uppercase is never produced and never accepted.
- **sha256** — SHA-256 (FIPS 180-4) over exactly the bytes stated.
- **base64** — RFC 4648 §4, the standard alphabet `A–Z a–z 0–9 + /`, with `=` padding, no line
  breaks, and *canonical* (§3): the string re-encodes to itself. The URL-safe alphabet is never
  produced and never accepted.
- **ed25519** — RFC 8032 "pure" Ed25519: no pre-hashing, no context string, 32-byte public keys,
  64-byte signatures. Signatures are deterministic, so signing the same bytes twice with the same
  key produces the same signature.
- **Strings** are sequences of UTF-16 code units, as in ECMAScript. Every length limit in this
  document counts UTF-16 code units — not bytes, not code points. `"😀"` has length 2. No Unicode
  normalization is ever applied: a string is hashed and compared exactly as its code units stand,
  so a precomposed `é` (U+00E9) and `e` + U+0301 are two different strings with two different
  hashes.
- **Regular expressions** use ECMAScript syntax without the `u` flag, matching on UTF-16 code
  units. `\d` is `[0-9]`. `\s` is the ECMAScript white-space set: U+0009, U+000A, U+000B, U+000C,
  U+000D, U+0020, U+00A0, U+1680, U+2000–U+200A, U+2028, U+2029, U+202F, U+205F, U+3000, U+FEFF.
  An implementation whose engine defines `\s` as ASCII only (RE2, for one) must widen it to that
  set where a rule below uses `\s`. `spec/vectors/receipt.json` carries a URL with a U+00A0 in it
  precisely to catch an engine that does not.
- **Integer** — a JSON number whose mathematical value is a whole number with
  |n| ≤ 9007199254740991 (2^53 − 1). See §1.4 for why the textual form of the token does not
  matter and the value does.
- **Timestamp** — `YYYY-MM-DDTHH:MM:SSZ`, UTC, seconds precision, matching the `timestamp`
  pattern in §4.1. Never a fraction, never an offset. The reference implementation checks the
  shape only, not calendar validity.
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
`unpaired surrogate at $.issuer.url`, `unsupported value at $.u`.

For a verifier, every one of those failures is a `schema` failure (§12, check 1), never a crash and
never a different hash. In particular: **an unpaired surrogate anywhere in the input is a `schema`
failure.** A JSON decoder that quietly substitutes U+FFFD for a lone surrogate escape (`\ud83d` with
no low surrogate after it) would hand the verifier a different document than the one on disk, so
such a verifier must pre-check the raw bytes for a lone surrogate escape before decoding, and
refuse the file when it finds one.

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

"Everything else" includes U+007F (DEL), U+0080 and above, U+00A0, U+2028 and U+2029, and all
non-ASCII text. A surrogate pair (a high surrogate U+D800–U+DBFF immediately followed by a low
surrogate U+DC00–U+DFFF) is emitted as the four-byte UTF-8 encoding of the code point it names. A
lone surrogate has no UTF-8 encoding and is an error, not an escape — see §1.1 for what a verifier
does with one. `/` is never escaped. `\uXXXX` is never used for a unit at or above U+0020, and the
hex digits of a `\u` escape are always lowercase.

Object keys are serialized by the same rule.

### 1.6 Arrays

`[`, the elements serialized and joined by `,`, `]`. Order is preserved exactly as given; arrays
are never sorted. An empty array is `[]`.

### 1.7 Objects

`{`, the members serialized as `"key":value` and joined by `,`, `}`. An empty object is `{}`.

Members are sorted by key. Keys are compared **after unescaping** — as the sequences of UTF-16
code units they denote, not as the escaped text that spelled them in the input — unit by unit,
numerically; where one key is a prefix of another the shorter sorts first; the empty key sorts
first of all. This is RFC 8785 §3.2.3 and the default order of ECMAScript `Array.prototype.sort()`.
It is not code-point order, not byte order of the UTF-8 encoding, and not numeric order: the keys
`"1"`, `"10"`, `"9"` sort in exactly that order, because U+0031 is below U+0039, whatever an
implementation's object model does with integer-looking keys. A key whose first code unit is a
high surrogate (U+D800–U+DBFF, the start of any character above U+FFFF) sorts *before* a key
starting with U+E000–U+FFFF. Concretely, for the four one-character keys U+FFFF, U+1F600 (`😀`, the
units U+D83D U+DE00), U+E000 and U+D7FF, the order is U+D7FF, U+1F600, U+E000, U+FFFF — the
surrogate pair lands between U+D7FF and U+E000, where its first unit puts it, not after U+FFFF
where its code point would.

**Duplicate member names are refused.** An object in which the same key (after unescaping) occurs
twice — `{"a":1,"a":2}`, or `{"a":1,"\u0061":2}` — is a `schema` failure. A parser that keeps the
last occurrence, as most do, would let two verifiers hash two different bodies from one file, so a
verifier must detect the duplicate in the raw text before or while parsing, not after. The
reference implementation does it with a single pass over the text that tracks member names per
object. The server never emits a duplicate.

Sorting applies at every level of nesting, and to objects inside arrays. Arrays themselves keep
their order.

### 1.8 Output

The canonical bytes are the UTF-8 encoding of the string produced above, with no byte-order mark
and no trailing newline. Every hash in §2 is over these bytes.

### 1.9 Input

The input to a verifier is a JSON *text* whose top-level value is an object: a receipt (§4), a
projection (§11), a root file (§9). A top-level array, string, number or literal is a `schema`
failure. A byte-order mark is not JSON: a file that starts with U+FEFF is a `schema` failure. JSON
whitespace between tokens, member order and the spelling of number tokens (§1.4) are all
irrelevant, because the verifier re-canonicalizes what it read.

### 1.10 Worked examples

From `spec/vectors/canonical.json`:

```
{}                                          → {}
{"b":1,"a":2,"C":3,"_":4}                   → {"C":3,"_":4,"a":2,"b":1}
{"ab":1,"a":2,"aa":3,"":4}                  → {"":4,"a":2,"aa":3,"ab":1}
{"9":1,"10":2,"1":3}                        → {"1":3,"10":2,"9":1}
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
- **Canonical base64.** Every base64 value in this format — a signature, a public key — must be
  *canonical*: the standard alphabet, exact `=` padding, no whitespace, and the unused low bits of
  the last symbol zero, so that decoding the string and re-encoding the bytes reproduces the
  string exactly. A 32-byte key is always 44 characters matching the `pubkey-b64` pattern of §4.1;
  its 43rd symbol carries two data bits and four bits that must be zero, so only `A`, `Q`, `g` or
  `w` can stand there. A 64-byte signature is always 88 characters matching `sig-b64`; its 86th
  symbol carries four data bits and two that must be zero. A decoder that tolerates non-zero
  unused bits, a missing pad, the URL-safe alphabet or stray characters reads the same bytes from
  several spellings; this format allows exactly one spelling, and any other is a `schema` failure
  before any cryptography runs. One key therefore has one spelling, and keys can be compared
  either as bytes or as text with the same result — the verifier compares bytes (§12, check 4).
- **Public keys.** The 32 raw Ed25519 public-key bytes in canonical base64. This is the form used
  everywhere — inside receipts, in `keys.json`, in the vectors, in a pinned key set. It relates to
  the DER SubjectPublicKeyInfo encoding by a fixed 12-byte prefix:
  `SPKI = 302a300506032b6570032100 ‖ raw32`, so either form converts to the other without an ASN.1
  parser.
- **Verification.** Decode the public key (must be canonical base64 of 32 bytes) and the
  signature (must be canonical base64 of 64 bytes), decode `self_hash` (must be 32 bytes), run
  Ed25519 verify. Any decoding failure is a verification failure, never an error.
- **Signature entries.** A receipt's `signatures` array holds objects
  `{"key_id", "alg": "ed25519", "sig", "role"}` with `role` either `"issuer"` or `"counter"`. A root
  file's `signatures` array holds `{"key_id", "alg": "ed25519", "sig"}` — no `role`. In both, `sig`
  is over the containing document's `self_hash`.
- **The issuer signature.** A receipt carries **exactly one** entry whose `role` is `"issuer"`. Zero
  such entries, or two or more, is a `signature` failure (§12, check 3) — the first says the
  receipt was never issued, the second that it cannot say by whom. The one entry's `key_id` must
  equal `issuer.key_id`; its `sig` is verified against `issuer.public_key`, and that key is then
  compared with the pinned set (§12, check 4). A `"counter"` entry is a second party's signature
  added after issue; version 1 verifiers do not verify counter signatures and must not fail a
  receipt for carrying one.

## 4. Receipt v1

A receipt is a JSON object. The rules that hold for every object in it:

- **Strict.** Every member listed is required and no member not listed is allowed. An unknown
  member anywhere — top level, inside a claim, inside a retriever — is a schema failure.
- **Nullable means explicit.** A member marked `or null` is present and `null` when it has no
  value. Members are never omitted.
- **No free text.** Every string is an enum, a digest, base64, a URL with no whitespace, a
  timestamp, a lowercase token or a shape-checked identifier. A verifier enforces the shapes;
  the intent behind them is that a sentence from somebody's document cannot fit through any of
  them.
- Member order in the file is irrelevant; the canonical form (§1) sorts.

### 4.1 Primitive shapes

Every string shape is a name below, defined by a pattern (§0's regular-expression conventions)
and, where given, a maximum length in UTF-16 code units. The tables that follow refer to these
names.

```
hex64          ^[0-9a-f]{64}$
timestamp      ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$
date           ^\d{4}-\d{2}-\d{2}$
http-url       ^https?:\/\/[^\s"'<>\\^`{|}]+$                                    length ≤ 2000
media-type     ^[a-z0-9][a-z0-9!#$&^_.+-]{0,80}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,80}$  length ≤ 160
extractor      ^[a-z0-9]+(?:[.-][a-z0-9]+)*(?:@[0-9a-z.-]+)?$                     length ≤ 40
model-id       ^[a-z0-9][a-z0-9._-]{1,63}$
semver         ^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$
key-id         ^eb-(?:receipt|root)-[a-z0-9-]{1,20}$
pubkey-b64     ^[A-Za-z0-9+/]{43}=$          and canonical, §3
sig-b64        ^[A-Za-z0-9+/]{86}==$         and canonical, §3
token(N)       ^[a-z][a-z0-9_]*$             length ≤ N
receipt-id     ^eb_[abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789]{16}$
doi-value      ^10\.\d{4,9}\/\S+$            length ≤ 200
pmid-value     ^\d{1,9}$
case-cite      one pattern, written here across four lines (it contains no literal whitespace):
               ^(?:\d{1,4}\s[A-Z][A-Za-z0-9.&'-]{0,12}(?:\s[A-Z0-9][A-Za-z0-9.]{0,7}){0,2}
                 |\[\d{4}\]\s\d{1,3}\s[A-Z][A-Za-z0-9.&'-]{0,12}(?:\s[A-Z0-9][A-Za-z0-9.]{0,7})?
                 |\[\d{4}\]\s[A-Z][A-Za-z0-9.&'-]{0,12}(?:\s[A-Z0-9][A-Za-z0-9.]{0,7}){0,2}
               )\s\d{1,6}$                                                          length ≤ 30
retriever-id   ^[A-Za-z0-9_-]{1,16}$
vantage        ^[a-z][a-z0-9_-]{0,23}$
archive-job    ^[A-Za-z0-9_.:-]{1,80}$
domain         ^[a-z0-9][a-z0-9._-]*$        length ≤ 253
```

Notes on the shapes:

- `http-url` is an absolute `http` or `https` URL with no whitespace (§0's `\s`, so a U+00A0
  inside it is refused) and none of the characters double quote, single quote, `<`, `>`,
  backslash, caret, backtick, `{`, pipe, `}`.
- `media-type` is a bare lowercase `type/subtype`, parameters stripped.
- `extractor` names a tool at a version: `unpdf@1`, `mammoth@1`, `paste`.
- `key-id` is the shape a receipt may name; production key ids are narrower (§13).
- `token(N)` is a lowercase machine word, never a sentence.
- `receipt-id` is `eb_` plus 16 characters from a 56-symbol alphabet with no `0 O 1 l I`.
- `case-cite` is a reporter or neutral citation of at most five whitespace-separated tokens and
  30 characters. It opens with a volume of one to four digits (`410 U.S. 113`, `2019 SCC 5`), or a
  bracketed four-digit year (`[2019] EWHC 12`), or a bracketed year followed by a volume of one to
  three digits (`[2010] 1 AC 123`, `[2019] 2 WLR 456`, `[2020] 1 All ER 123`). Then come one to
  three reporter tokens — the first starts with a capital letter and continues with letters,
  digits, `.`, `&`, `'` or `-` up to 13 characters in all; each further one starts with a capital
  letter or a digit and continues with letters, digits or `.` up to 8 characters in all — except
  that only two reporter tokens may follow a year-plus-volume, which is what keeps every shape
  inside five tokens. Then a page of one to six digits. Exactly one whitespace character separates
  tokens (the engine collapses runs before sealing). `123 S. Ct. 456`, `123 F. Supp. 2d 456`,
  `123 F.3d 456`, `12 Cal. App. 4th 345`, `12 N.Y.S.2d 34`, `[2020] UKSC 1`, `[2015] 2 Lloyd's Rep 123`
  all fit; a sentence that happens to start with a year and end with a number does not, and
  neither does a six-token citation such as `[2020] 1 Cr App R 123`.

The non-string primitives:

| name | rule |
|---|---|
| integer | §0 |
| bp | integer 0 ≤ n ≤ 10000 (basis points) |
| span | a two-element array `[start, end]` of integers with `0 ≤ start ≤ end` |

### 4.2 Top level

| member | type | rule |
|---|---|---|
| `v` | integer | the literal `1` |
| `kind` | string | `"exhibitb.receipt"` (chained) or `"exhibitb.receipt.unchained"` (§5) |
| `id` | receipt-id | |
| `seq` | integer ≥ 1 or null | position in the chain; `null` exactly when unchained |
| `prev_hash` | hex64 or null | `self_hash` of the receipt at `seq − 1`, or the genesis constant (§6) at `seq` 1; `null` exactly when unchained |
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
| `signatures` | array of signature, ≤ 8 | §3; exactly one `"issuer"` entry in an issued receipt |

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
| `quote_hmac` | hex64 or null |
| `doc_span` | span — where the claim sits in the extracted text |
| `locator` | object, §4.7 |
| `source_of` | `"body"` or `"list"` — which of the two kinds of claim this is. Required from `engine.version` `0.2.0`; a `0.1.x` body may omit it and is read as `"body"` (§15) |
| `level` | `"EXISTS"` or `"SAYS"` — how far the check went |
| `exists` | object, §4.8.1 |
| `says` | object, §4.8.2 |
| `refutation_attempted` | boolean |
| `dissent` | the literal `null` — always; an adversarial second opinion never reaches a sealed receipt |

A claim is a passage of the document that leans on an outside source, and there are two kinds.
`source_of` says which.

`"body"` is a sentence, or a short contiguous passage, that cites a source — by printing its
identifier, or through a marker the document's own lists answer.

`"list"` is an entry of one of the document's citation lists that no passage cites. Every such list
counts, wherever the document puts it: the section headed References, Bibliography, Works Cited or
the like; the footnotes or endnotes that carry the full citations; a table of authorities; and a
list of publications an author sets out as their own work, a curriculum vitae attached to the
document included. Each is the document's statement of what it rests on, so each entry is resolved
and fetched like any other claim. An entry that some passage does cite is not repeated as a claim
of its own: it is checked through the passage that cites it, which is a `"body"` claim.

A `"list"` claim attributes no words to its source, so it carries `quote_hmac: null` and
`level: "EXISTS"`; its `doc_span` covers the entry where it is printed. Beyond that the two are
checked the same way, and a verifier need not tell them apart: `source_of` is there so a reader can
be told "five cited claims and a hundred and forty-four listed sources" rather than one flat tally.

### 4.7 `locator`

Discriminated on `type`:

| `type` | `value` | `url` |
|---|---|---|
| `"url"` | http-url | http-url or null |
| `"doi"` | doi-value | http-url or null |
| `"pmid"` | pmid-value | http-url or null |
| `"case"` | case-cite | http-url or null |
| `"unsupported"` | hex64 — the HMAC of the citation string (§4.5), because the string itself would be the claimant's own text | the literal `null` |

### 4.8 Verdicts

#### 4.8.1 `exists`

| member | rule |
|---|---|
| `verdict` | one of the five below |
| `final_url` | http-url or null — where the source was finally read from, after redirects |
| `http_status` | integer 0…599 or null |
| `fetched_at` | timestamp or null |
| `content_type` | media-type or null |
| `bytes` | integer ≥ 0 or null |
| `content_sha256` | hex64 or null — SHA-256 of the fetched bytes |
| `text_sha256` | hex64 or null — SHA-256 of the text extracted from them |
| `retrievers` | array ≤ 8 of retriever objects, §4.8.3 |
| `retriever_disagreement` | boolean — two retrievers fetched different bytes |
| `single_retriever` | boolean — only one vantage answered |
| `registry` | object `{ agency: token(32), status: integer 0…999, method: token(16) or null }` or null — the registry consulted for a doi/pmid/case locator, what it answered, and how it was asked |
| `archive_url` | http-url or null |
| `archive_status` | `"archived"`, `"requested"`, `"failed"` or `"skipped"` |
| `archive_job_id` | archive-job or null |

`method` names the call that answered, for a registry that can be asked in more than one way.
The case registry has two: `"lookup"` is the exact citation lookup, which needs a credential and
answers about the citation itself; `"search"` is the open search, which needs none and answers with
the records that carry the citation. A search confirmation is `200` only when exactly one record
prints the citation asked about, matched on spacing and case alike; two such records is `300`
(ambiguous). No record printing the citation is a real absence (`404`) only when the page the
registry returned was its whole answer **and** the citation's reporter is one the registry indexes
comprehensively — the federal reporters and the regional and state reporters the engine names. A
citation in any other reporter, or a neutral citation with no reporter token at all (`[2019] EWHC
123`), the registry may simply not carry, so its silence is not a denial: the answer is recorded as
`200` with no URL. So too when records were left unreturned behind the page, or the page never said
how many matched at all. Each of these `200`-with-no-URL cases rule 3 below reads as
`SOURCE_UNREACHABLE`, never as "does not exist" — an unindexed citation is never accused of not
existing. The exact lookup applies the same coverage gate to its own `404`. A registry with only one
way of being asked writes `null`. `method` is required from
`engine.version` `0.2.0`; a `0.1.x` body may omit it and is read as `"lookup"` (§15).

`verdict` values:

| value | meaning |
|---|---|
| `RESOLVED` | at least one retriever read a 2xx answer with a body; `content_sha256` and `bytes` cover the whole body even when it ran past the size kept for text (SAYS then reports `too_large`) |
| `RESOLVED_NO_ACCESS` | the source exists and answered, but its content could not be read: 401, 402, 403, 407, 429 or 451 from the URL, or the case registry answering 300 (ambiguous) |
| `NOT_FOUND` | the identifier or the URL does not exist: the registry answered 404 or 400, or the URL itself answered 404 or 410 — and neither retriever read a 2xx body |
| `SOURCE_UNREACHABLE` | the network did not answer, answered 5xx, or the body never finished within the deadline — or there was no URL to fetch because the registry did not answer, refused the lookup (401, 403, 407, 429) or failed (5xx): nothing is known about the source either way |
| `UNSUPPORTED_LOCATOR` | the citation is of a kind the engine cannot resolve; its locator is `unsupported` |

How the engine decides, in order — every input is a field beside the verdict, so a reader can
re-derive it:

1. the locator is `unsupported` → `UNSUPPORTED_LOCATOR`;
2. the registry answered 404 or 400 and neither retriever read a 2xx body → `NOT_FOUND`; the
   registry answered 300 and neither did → `RESOLVED_NO_ACCESS`;
3. there was nothing to fetch (the registry gave no URL) and rule 2 did not apply →
   `SOURCE_UNREACHABLE`: the registry did not answer, refused the lookup (401, 403, 407, 429),
   failed (5xx), or answered without a page to read. A refusal is a fact about the lookup, not
   about the source; the status stays beside the verdict in `registry`;
4. either retriever read a 2xx body → `RESOLVED`, whatever the registry said (its answer stays
   beside the verdict in `registry`);
5. otherwise the URL's own status decides: 401/402/403/407/429/451 → `RESOLVED_NO_ACCESS`;
   404/410 → `NOT_FOUND`; anything else, no answer and 5xx included → `SOURCE_UNREACHABLE`.

So a registry 404 alone makes `NOT_FOUND` only when neither retriever read the page: what was read
outranks what the registry said. Only a registry answer of 404 or 400 ever makes `NOT_FOUND`: a
registry that refuses or rate-limits the lookup has said nothing about the identifier.
`NOT_FOUND` and `SOURCE_UNREACHABLE` are different facts about different parties and are never
merged.

#### 4.8.2 `says`

| member | rule |
|---|---|
| `verdict` | `"MATCH"`, `"DRIFT"`, `"NOT_FOUND"` or `"NOT_RUN"` |
| `reason` | token(48) or null — why, when `NOT_RUN`. The engine writes `no_text_layer` (read, but no text could be extracted), `too_large` (read and hashed whole, but the body ran past the size kept for text), `no_access`, `unreachable`, `not_found`, `unsupported_locator` (the source's EXISTS verdict left nothing to check), `no_registry_text` (the case was confirmed only by the registry's open search, whose resolved page the registry guards behind a challenge, so no opinion text was available to run against), `no_quote`, `quote_too_short`, `free_tier`, `pending`, `not_requested`; not a closed list in version 1 |
| `quoted_span` | span or null — where in the source text the match was found |
| `match_kind` | `"exact"`, `"overlap"` or null |
| `overlap_bp` | bp or null — how much of the quote the source carries, in basis points |

`MATCH` means the quote was found at or above `engine.says_thresholds.match_bp`; `DRIFT` means
it was found between `drift_min_bp` and `match_bp`; `NOT_FOUND` means nothing at or above
`drift_min_bp`; `NOT_RUN` means the SAYS check did not run, and `reason` says why.

#### 4.8.3 A retriever

| member | rule |
|---|---|
| `id` | retriever-id |
| `vantage` | vantage |
| `status` | integer 0…599, or the literal `"unavailable"` |
| `content_sha256` | hex64 or null |

### 4.9 `counts`

Twelve integers ≥ 0: `claims`, `not_checked`, `resolved`, `no_access`, `not_found`, `unreachable`,
`unsupported`, `says_match`, `says_drift`, `says_not_found`, `says_not_run`, `holds_attempted`.
All but `not_checked` are the issuer's tallies over `claims`: the five exists tallies (`resolved`,
`no_access`, `not_found`, `unreachable`, `unsupported`) each count the claims with that
`exists.verdict` and sum to `claims`; the four says tallies do the same for `says.verdict`;
`holds_attempted` counts the claims with `refutation_attempted` true.

`not_checked` is the one tally not derived from `claims`, and the only one that describes what the
receipt leaves out: citations the engine found in the document — a cited passage, or an entry of one
of its lists — and did not check, because a budget on how many claims one receipt may carry ran out.
Zero means the receipt covers every citation the engine found. A receipt over the first four hundred
entries of a six-hundred-entry bibliography says so here, and a reader who is not told this would
have no way to know the difference. `not_checked` is required from `engine.version` `0.2.0`; a
`0.1.x` body may omit it and is read as `0` (§15).

They are inside the hashed body, so they cannot be altered without failing `self_hash`; a version 1
verifier does not cross-check them against the claims.

### 4.10 `models`

Each entry is `{ role: token(24), model: model-id }`.

### 4.11 `engine`

| member | rule |
|---|---|
| `name` | the literal `"exhibitb"` |
| `version` | semver — the engine that sealed the body. `0.2.0` is the version the format was finalized at; what a `0.1.x` body may omit is in §15 |
| `normalize` | the literal `"norm@1"` — the text normalization the HMACs and spans were computed under |
| `says_thresholds` | `{ match_bp: bp, drift_min_bp: bp }` — currently `10000` and `7500` |

### 4.12 A signature

`{ key_id: key-id, alg: "ed25519", sig: sig-b64, role: "issuer" or "counter" }` — see §3.

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
its recorded `self_hash` — including a stored document that cannot be canonicalized or parsed at
all), `signature` (there is not exactly one issuer signature, or it does not verify under the key
published for its `key_id`, or the embedded key differs from the published one), `root` (a rooted
day's receipts no longer hash to the stored root; `seq` is that root's `last_seq`, or 0 for an empty
day). The server verifies signatures against the keys it has published for the `key_id`, never
against the key embedded in the receipt, so a receipt cannot vouch for itself. The public answer
is incremental — it trusts the prefix it walked before and checks only the receipts sealed since —
and is cached for sixty seconds. Rooted days are re-checked on every call: each rooted receipt is
re-derived from its stored bytes and the day's Merkle root recomputed, so a rewrite of an
already-rooted receipt is reported at once. A rewrite of a receipt in a day not yet rooted sits
inside the trusted prefix and surfaces at the nightly replay, which walks from genesis; its answer
is what the public endpoint serves from then on, until the head moves.

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
| `first_seq` | integer ≥ 1 or null — `seq` of the day's first leaf; `null` on an empty day |
| `last_seq` | integer ≥ 1 or null — `seq` of its last leaf; `null` on an empty day |
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
2. Once stored a root file is never rewritten. If a receipt is nevertheless sealed with an
   `issued_at` on a day that already has a root — which can only happen when the server's clock
   steps backwards across midnight after 00:05 UTC — the day's leaves no longer hash to the
   published root, and the server treats that exactly as it would treat tampering: the proof
   endpoint answers *pending* for **every** receipt of that day, the one that arrived late included,
   and the nightly replay reports `first_broken` with `reason` `root` at that day's `last_seq`,
   which mails the operator. There is no automatic repair, because rewriting a published root is
   the one thing this design forbids; the operator must resolve it by hand. Operationally: the
   host clock must be disciplined by slewing, not stepping, and the five-minute margin before the
   root job is the tolerance for ordinary drift.
3. The file is published to a public repository as `roots/<date>.json`, and again as
   `roots/latest.json`, each containing the canonical bytes followed by one `\n`. The issuer also
   serves it at `GET /chain/root/<date>` as the canonical bytes with no trailing newline (404 until
   the day is rooted). Strip a trailing newline before hashing; better, parse and re-canonicalize.
4. To verify a root file: parse (§1.9); schema as above; `self_hash` recomputed per §2 must equal
   the stated one; the first signature's `key_id` must equal `key_id`, and its `sig` must verify
   under the pinned public key for that `key_id` (§13) — the file does not embed the key, so an
   unpinned root key means the signature cannot be checked. Across consecutive files, each
   `prev_root` must equal the previous `root`.

The root file in `spec/vectors/root.json` covers three receipts of 2026-09-03; its `self_hash`,
`root` and signature are recorded there and must be reproduced exactly (§14).

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
hash to the stored root (§9 rule 2), so a served proof always points at a tree that was signed.

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
- Every other member of a claim stays as it is, `source_of` and `level` included: neither can
  identify the document, and without `source_of` a projection could not be read as "so many cited
  claims and so many listed sources".
- Everything else is byte-for-byte the receipt: `id`, `seq`, `prev_hash`, `issued_at`, `issuer`,
  `document`, `binding`, `counts`, `models`, `engine`, **`self_hash` and `signatures`**. A
  projection carries the *receipt's* hash and signatures so a holder of the full receipt can link
  the two; it is a view of a receipt, not a document that hashes to itself.
- A projection is **signed in its own right**. It carries one extra top-level member,
  `projection_sig` (sig-b64, §4.1) — a member a sealed receipt never has, which is also what tells a
  projection from a receipt. `projection_sig` is `ed25519(receipt key, projection-self-hash)`, where
  the **projection self-hash** is `sha256` of the canonical bytes (§1) of the projection with only
  its top-level `projection_sig` removed — every other member inside it, `self_hash` and
  `signatures` among them. So the whole visible surface of a projection — its per-claim verdicts,
  its counts, its hashes, its `http_status`, its domains and its `registry` — is bound by
  `projection_sig`, not only by the receipt's `self_hash`. The signature is over the 32 raw bytes of
  that hash, exactly as a receipt signature is over the 32 raw bytes of `self_hash` (§3), and it is
  made with the same receipt key, so `issuer.public_key` verifies it.
- The server validates and signs every projection at seal time, so a stored projection always parses
  and always carries a valid `projection_sig`. A projection stored before this signature existed is
  re-projected from the sealed body and signed under the receipt's own key — once at boot, and
  again on read should one have been missed — so every projection the issuer serves carries one.
  A projection of a `0.1.x` body carries exactly what that body carries (§15): it omits what the
  body omits.

`domain` (the `domain` shape of §4.1, or `null`):

- `type` `"url"`: the registrable host of `exists.final_url` when it is not `null`, else of
  `locator.value`.
- `type` `"doi"`, `"pmid"`, `"case"`: `exists.registry.agency`, or `null` when `registry` is `null`.
- `type` `"unsupported"`: `null`.

Registrable host of a URL: parse it; take the hostname, lowercased; drop a leading `www.`; if what
is left is empty, is bracketed (an IPv6 literal) or contains `:`, the answer is `null`; if any
label is empty (`www.`, `a..b`), `null`; if it is an IPv4 literal, keep it whole; if it has two
labels or fewer, keep it whole; otherwise keep the last two labels — or the last three when the
last two are one of `ac.jp`, `ac.uk`, `co.in`, `co.jp`, `co.nz`, `co.uk`, `co.za`, `com.au`,
`com.br`, `edu.au`, `gov.au`, `gov.uk`, `net.au`, `org.au`, `org.uk`. Finally, anything that does
not match the `domain` shape is `null`. So `https://www.example.org/reports/q1.pdf` →
`example.org`, `https://pubmed.ncbi.nlm.nih.gov/31234567/` → `nih.gov`,
`https://www.bmj.co.uk/content/1` → `bmj.co.uk`, `https://[::1]/x` → `null`, `https://www./x` →
`null`. A verifier never needs to compute this; it is listed so the projection is fully specified.

A verifier given a projection instead of a receipt (the JSON the public page serves) runs the
five checks with checks 2 and 3 taken over the projection itself: check 1 recognises the projection
shape; check 2, `projection_self_hash`, recomputes the projection self-hash above and reports it;
check 3, `projection_signature`, verifies `projection_sig` over that hash under `issuer.public_key`;
checks 4 and 5 run as for a receipt. A genuine projection therefore passes outright — exit 0, the
same as a receipt — and any altered field fails `projection_signature`, because the recomputed hash
no longer matches what was signed. The sealed body with its cited URLs is still not present, so the
receipt's own `self_hash` is not recomputed on a projection; it does not need to be, since
`projection_sig` already binds every byte a projection carries.

## 12. Verifier checks and exit codes

Input: one JSON text — a receipt or a projection — read from a file or standard input. Optional
inputs: a pinned key set (§13; the release build carries one), a root file and a proof (§10).

The checks, in this order, each with a `name`, a `status` of `pass`, `fail`, `warn` or `skip`, and
a free-form `detail`:

A receipt and a projection run the same five checks; checks 2 and 3 differ only in what they are
taken over. The names below are for a receipt, with the projection's name after the slash.

| # | name | pass | fail | warn | skip |
|---|---|---|---|---|---|
| 1 | `schema` | see below | see below; `detail` names the first offending path | — | — |
| 2 | `self_hash` / `projection_self_hash` | receipt: §2 recomputed equals its `self_hash`. projection: the projection self-hash (§11) is recomputed and reported — it is `pass` for any schema-valid projection, since a projection carries no stored copy of this hash to compare against; check 3 is what it is verified through | receipt: the recomputed hash does not equal `self_hash` | — | schema failed |
| 3 | `signature` / `projection_signature` | receipt: exactly one `"issuer"` entry, whose `key_id` equals `issuer.key_id` and whose `sig` verifies under `issuer.public_key` over `self_hash`. projection: `projection_sig` verifies under `issuer.public_key` over the projection self-hash of check 2 | receipt: no `"issuer"` entry; more than one; its `key_id` differs from `issuer.key_id`; or the signature does not verify. projection: `projection_sig` does not verify over the recomputed hash — so any altered field fails here | — | schema failed |
| 4 | `key_pinned` | the pinned set has `issuer.key_id`, and its 32 decoded key bytes equal the 32 decoded bytes of `issuer.public_key` | the pinned set has `issuer.key_id` with *different* bytes — someone signed under the issuer's key id with a key of their own; or the pinned entry itself is not canonical base64 of 32 bytes | `issuer.key_id` is not in the pinned set — perhaps a key newer than this verifier | no pinned set was supplied; schema failed |
| 5 | `chain_fields` | kind `"exhibitb.receipt"` with integer `seq` ≥ 1 and hex64 `prev_hash` | a chained receipt missing either; an unchained one carrying either | — | kind `"exhibitb.receipt.unchained"` with both `null`; schema failed |

**Check 1 in full.** In this order: the text is read and refused if it starts with a byte-order
mark, is not JSON, or carries a duplicate member name anywhere (§1.7, §1.9); the top-level value
must be an object; then the value is matched against the **receipt schema first** (§4) and, only
if that fails, against the **projection schema** (§11); if neither matches, `detail` names the
first path the receipt schema rejected. Finally every string in the matched value must be
canonicalizable (§1.1): an unpaired surrogate anywhere is a `schema` failure with `detail`
`unpaired surrogate at <path>`. After a `schema` failure checks 2–5 are all reported as `skip`,
under the receipt names.

Every other check runs regardless of earlier failures, so the report is complete;
`first_failure` is the name of the first check whose status is `fail`, or `null`. `ok` is true
when no check failed. A `warn` never makes `ok` false.

Check 3 verifies against the key *embedded* in the receipt on purpose: it establishes that the
document (or projection) is internally consistent, and check 4 then establishes whether that key is
the issuer's. Reporting them separately is what lets a verifier say "well-formed and signed, but not
by a key I know" rather than merely "bad". Keys are compared as bytes in check 4; since every key in
this format has exactly one canonical spelling (§3), comparing the strings gives the same answer for
any input that reached check 4.

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
| 2 | no check failed, but at least one is `warn`: the verifier could not establish everything — a key is not pinned, a changed or unreachable source, a proof is still pending |
| 64 | usage: unrecognised flags, a missing or unreadable input file. A file that reads but is not a receipt is exit 1 with `first_failure` `schema`, not 64 |

Machine output, when requested, is `{"ok", "checks": [{"name", "status", "detail"}], "first_failure"}`
with the checks in the order above. `detail` strings are for people and are not part of this
contract.

## 13. Key pinning and `keys.json`

The issuer publishes every key it has ever signed with at `<issuer url>/keys.json`
(`cache-control: public, max-age=300`), from its first boot on — the list is never empty:

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
  `eb-root-2026-09` — named for the month the key was made, and `eb-<purpose>-<YYYY-MM>-2`, `-3`,
  … for a further key made in the same month after the earlier one was retired. One key id names
  one public key for all time; the issuer never publishes a second key under an existing id and
  never re-activates a retired one. The production shape is

  ```
  ^eb-(?:receipt|root)-\d{4}-\d{2}(?:-[2-9]|-[1-9]\d{1,2})?$
  ```

  while the receipt schema (§4.1, `key-id`) accepts the wider `^eb-(?:receipt|root)-[a-z0-9-]{1,20}$`
  so that the fixture keys below fit through it.
- **Purposes.** Receipts are signed with a `receipt` key, root files with a `root` key. A pinned
  set is therefore two lists; check 4 consults the `receipt` list, root verification the `root`
  list.
- **Pinning.** A release of the verifier compiles in the `{key_id, public_key}` pairs from
  `keys.json` at build time. Check 4 compares the receipt's embedded key against that set as
  decoded bytes: same bytes → `pass`; unknown id → `warn` (the receipt may be newer than the
  verifier: refresh the pinned set, or pass a freshly fetched `keys.json`); known id, different
  bytes → `fail`. A pinned entry that is not canonical base64 of 32 bytes is a `fail` too — it is
  the verifier's own configuration that is broken, and a broken pin must not pass. A verifier may
  accept a `keys.json` file on the command line in place of, or in addition to, its compiled set.
- **Fixture keys.** `spec/vectors/test-key.json` is `{"key_id": "eb-receipt-test",
  "private_pkcs8_b64", "public_key"}` — a committed Ed25519 key whose private half is public by
  design, so the vectors are reproducible. Its public key is
  `+OIf8AWG2M/e4fqmltCC+xtj9kmks5fAk3UjznkHRuQ=`. The root vector signs with the same key pair
  under the id `eb-root-test`. The issuer refuses to sign anything real with an id outside the
  production shape above, and a release verifier must not carry either fixture id in its pinned
  set; pin them only when running the vectors.
- **Private keys** never leave the issuer. Public keys are the only thing a verifier ever holds.

## 14. Vectors

All files are under `spec/vectors/`, generated by one deterministic script from the reference
implementation, so re-running it produces byte-identical files. They are pretty-printed JSON; the
canonical bytes a case is about are carried as string values inside them, never as the file's own
layout. Read each file with an ordinary JSON parser — except where a case is *about* the parser,
which the descriptions below call out.

### `canonical.json`

An array of `{"name", "input", "canonical"}`. For each case, canonicalize `input` (§1) and compare
the UTF-8 bytes with `canonical` (a string; encode it as UTF-8). Seventeen cases: empty object and
array; literals; key order for ASCII, prefixes, non-ASCII, the surrogate-pair edge and
digit-string keys (`"1"`, `"10"`, `"9"`); every escape; control characters; U+007F and U+0080
literal; non-ASCII pass-through; a literal U+00A0 (emitted as itself, like any unit at or above
U+0020); integers including 0, negatives and ±(2^53 − 1); array order; nested sorting; a
receipt-shaped fragment. Also check that parsing `canonical` and canonicalizing again returns the
same bytes.

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
  "projection":       its public projection (§11), signed with projection_sig,
  "projection_tampered": {"name", "first_failure", "receipt"} — a projection an attacker rewrote,
  "unchained":        {"receipt", "self_hash"} — the same body issued unchained,
  "legacy":           {"name", "engine_version": "0.1.0", "receipt", "self_hash", "projection"}
                      — a body sealed before the format was finalized (§15), and its projection,
  "tampered":         [{"name", "first_failure", "receipt"}, ×6]
}
```

With `key` as the pinned set: `receipt` must pass all five checks (exit 0);
`self_hash(receipt)` must equal `self_hash`; `sha256(canonical(receipt))` must equal
`canonical_sha256` — the integrity check for a downloaded file, distinct from the hash that is
signed. `projection` must pass all five checks (exit 0), with `projection_self_hash` and
`projection_signature` in place of `self_hash` and `signature`. `projection_tampered.receipt` — the
same projection with a count and a verdict rewritten while `self_hash`, `signatures` and
`projection_sig` are left byte-identical — must have `ok` false and `first_failure`
`projection_signature`. `unchained.receipt` must pass with `chain_fields` `skip` and hash to
`unchained.self_hash`. `legacy.receipt` — sealed at `engine.version` `0.1.0` with no
`claims[].source_of`, no `counts.not_checked` and no `registry.method` — must pass all five checks
and hash to `legacy.self_hash`, and `legacy.projection` must pass all five as a projection: this is
the case that catches a verifier which requires the three members regardless of the version, or
which fills them in and so hashes a different body. Each
`tampered[i].receipt` must have `ok` false and `first_failure` equal to
`tampered[i].first_failure`, with checks 2–5 `skip` whenever that is `schema`:

1. an edited `overlap_bp` → `self_hash`;
2. one flipped signature byte → `signature`;
3. an unknown `kind` → `schema`;
4. `issuer.url` carrying a lone high surrogate, present in the file as the six characters `\ud83d`
   with no low surrogate after it → `schema` (§1.1). This is the case that catches a decoder which
   substitutes U+FFFD: after such a substitution the string is a valid URL and every check passes,
   which is the wrong answer;
5. `claims[0].locator.url` carrying a literal U+00A0 (the character itself, not an escape) →
   `schema`, because U+00A0 is whitespace under the `http-url` shape (§0's `\s`). This is the case
   that catches a regular-expression engine whose `\s` is ASCII only;
6. the valid receipt — `engine.version` `0.2.0` — with `claims[].source_of`, `counts.not_checked`
   and `registry.method` removed → `schema`, at `$.claims[0].source_of` (§15). This is the case
   that catches a verifier which extends the `0.1.x` allowance to every version.

The exact `self_hash` and `canonical_sha256` values are in the file; the reference implementation
reproduces `receipt` byte for byte from its own fixtures, and so must any other.

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

## 15. Compatibility

The format was finalized at `engine.version` `0.2.0`. A body whose `engine.version` is `0.1.x` —
anything below `0.2.0` by comparison of the numeric `major.minor.patch` triple, a pre-release or
build suffix ignored — was sealed while the format was still being finalized and may omit three
members. A verifier reads such a body as if it carried:

| member | when absent, read as |
|---|---|
| `claims[].source_of` (§4.6) | `"body"` |
| `counts.not_checked` (§4.9) | `0` |
| `claims[].exists.registry.method` (§4.8.1) | `"lookup"` |

Nothing else is relaxed: every other rule of §4 holds for a `0.1.x` body exactly as written, a
member that is present must still match its shape, and an unknown member is still a `schema`
failure. From `0.2.0` on all three are required, and a body at or above `0.2.0` that omits any of
them fails `schema` at that path, `$.claims[0].source_of` first. The sealed bodies from before the
line are immutable and must keep verifying; nothing sealed after it may lean on the exception. The
rule is keyed on the sealed `engine.version` alone and applies to the receipt schema and the
projection schema alike: a projection of a `0.1.x` receipt carries exactly what the body carries
(§11), so it omits what the body omits. Each component of the triple is read as a signed 64-bit
integer, exactly as written; a version with a component that does not fit one —
`0.1.9223372036854775808`, say — is not below anything, whatever its other components say, and such
a body is read under the final rule.

Nothing is ever written into a body to fill the gap. A verifier that re-serialises what it read
must reproduce the absence, or its `self_hash` will not match — the read-as values above are for
what a verifier reports, never for what it hashes. `spec/vectors/receipt.json` carries one such
body with its projection under `legacy` (§14), and one copy at `0.2.0` with the same omissions
that must fail.

## 16. Known design notes

Accepted for version 1, and written down so a later revision starts from the fact.

- **No domain separation between the two signatures.** A receipt signature is ed25519 over the 32
  raw bytes of the receipt's `self_hash` (§3); `projection_sig` is ed25519 over the 32 raw bytes of
  the projection self-hash (§11). Both are made with the same receipt key, and both documents say
  `kind: "exhibitb.receipt"`, so nothing in the signed bytes says which of the two a signature is
  for. Cross-use fails today all the same: the two hashes are over different canonical texts (the
  projection self-hash covers `self_hash`, `signatures` and the projected claims; the receipt body
  carries the full locators and neither of those members), so a signature presented as the other
  kind fails `signature` or `projection_signature` unless someone found a second preimage across
  the two texts — and the strict schemas keep the two shapes apart before any cryptography runs: a
  receipt carrying `projection_sig` fails `schema` with `$.projection_sig: unknown member`, a
  projection without it with `$.projection_sig: missing member`. A future format version would
  prefix the signed bytes with a context label per signature (or give the projection its own
  `kind`); doing that now would move every signature and every vector for no change in what
  verifies.
