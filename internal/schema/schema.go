// Package schema is the strict-object validator behind the receipt (spec §4), projection (§11)
// and root file (§9) shapes: every listed member is required, nothing else is allowed, and every
// string shape is checked under the ECMAScript conventions of §0 — lengths in UTF-16 code units,
// \s the Unicode white-space set.
package schema

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/20012001amiramir/recheck/canonical"
	"github.com/20012001amiramir/recheck/merkle"
)

// Error names the first member that does not match, in the spec's path notation:
// $.claims[0].says.overlap_bp.
type Error struct {
	Path string
	Msg  string
}

func (e *Error) Error() string { return e.Path + ": " + e.Msg }

// ── shapes (§4.1) ─────────────────────────────────────────────────────────

// JSWhitespace is the ECMAScript \s set as a Go character-class body; RE2's \s is ASCII only.
const JSWhitespace = `\t\n\x0B\f\r \x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}`

// The case-cite pattern of §4.1, assembled from its three alternatives — a volume, a bracketed
// year, or a bracketed year and a volume of up to three digits — each followed by one to three
// reporter tokens (only two after a year-plus-volume, which keeps every shape inside five tokens)
// and a page, with exactly one whitespace character between tokens.
const (
	caseWS       = `[` + JSWhitespace + `]`
	caseReporter = `[A-Z][A-Za-z0-9.&'-]{0,12}`
	caseMore     = caseWS + `[A-Z0-9][A-Za-z0-9.]{0,7}`
	casePattern  = `\A(?:` +
		`[0-9]{1,4}` + caseWS + caseReporter + `(?:` + caseMore + `){0,2}` +
		`|\[[0-9]{4}\]` + caseWS + `[0-9]{1,3}` + caseWS + caseReporter + `(?:` + caseMore + `)?` +
		`|\[[0-9]{4}\]` + caseWS + caseReporter + `(?:` + caseMore + `){0,2}` +
		`)` + caseWS + `[0-9]{1,6}\z`
)

var (
	reTimestamp   = regexp.MustCompile(`\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z`)
	reDate        = regexp.MustCompile(`\A[0-9]{4}-[0-9]{2}-[0-9]{2}\z`)
	reMediaType   = regexp.MustCompile(`\A[a-z0-9][a-z0-9!#$&^_.+-]{0,80}/[a-z0-9][a-z0-9!#$&^_.+-]{0,80}\z`)
	reExtractor   = regexp.MustCompile(`\A[a-z0-9]+(?:[.-][a-z0-9]+)*(?:@[0-9a-z.-]+)?\z`)
	reModelID     = regexp.MustCompile(`\A[a-z0-9][a-z0-9._-]{1,63}\z`)
	reSemver      = regexp.MustCompile(`\A[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?\z`)
	reKeyID       = regexp.MustCompile(`\Aeb-(?:receipt|root)-[a-z0-9-]{1,20}\z`)
	rePubKey      = regexp.MustCompile(`\A[A-Za-z0-9+/]{43}=\z`)
	reSig         = regexp.MustCompile(`\A[A-Za-z0-9+/]{86}==\z`)
	reToken       = regexp.MustCompile(`\A[a-z][a-z0-9_]*\z`)
	reReceiptID   = regexp.MustCompile(`\Aeb_[abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789]{16}\z`)
	reDOI         = regexp.MustCompile(`\A10\.[0-9]{4,9}/[^` + JSWhitespace + `]+\z`)
	rePMID        = regexp.MustCompile(`\A[0-9]{1,9}\z`)
	reCase        = regexp.MustCompile(casePattern)
	reRetrieverID = regexp.MustCompile(`\A[A-Za-z0-9_-]{1,16}\z`)
	reVantage     = regexp.MustCompile(`\A[a-z][a-z0-9_-]{0,23}\z`)
	reArchiveJob  = regexp.MustCompile(`\A[A-Za-z0-9_.:-]{1,80}\z`)
	reDomain      = regexp.MustCompile(`\A[a-z0-9][a-z0-9._-]*\z`)
	reWhitespace  = regexp.MustCompile(`[` + JSWhitespace + `]`)
)

// Length limits, in UTF-16 code units.
const (
	MaxURLLen    = 2000
	MaxMediaType = 160
	MaxExtractor = 40
	MaxDOI       = 200
	MaxCaseCite  = 30
	MaxDomain    = 253
)

// UTF16Len counts UTF-16 code units, which is what every length limit in the spec counts.
func UTF16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// A Shape returns "" when s is acceptable, else the reason it is not.
type Shape func(s string) string

// Re makes a Shape from a regular expression.
func Re(r *regexp.Regexp, why string) Shape {
	return func(s string) string {
		if !r.MatchString(s) {
			return why
		}
		return ""
	}
}

// MaxLen caps a Shape at n UTF-16 code units.
func MaxLen(n int, inner Shape) Shape {
	return func(s string) string {
		if UTF16Len(s) > n {
			return "longer than " + strconv.Itoa(n) + " characters"
		}
		return inner(s)
	}
}

// Token is token(N): a lowercase machine word of at most n units.
func Token(n int) Shape { return MaxLen(n, Re(reToken, "expected a lowercase token")) }

// Hex64 is 64 lowercase hex digits.
func Hex64(s string) string {
	if _, ok := merkle.ParseHash(s); !ok {
		return "expected a lowercase hex sha256"
	}
	return ""
}

// HTTPURL is `^https?:\/\/[^\s"'<>\\^`{|}]+$` with the ECMAScript \s, at most 2000 units.
func HTTPURL(s string) string {
	if UTF16Len(s) > MaxURLLen {
		return "URL longer than 2000 characters"
	}
	rest, ok := strings.CutPrefix(s, "https://")
	if !ok {
		rest, ok = strings.CutPrefix(s, "http://")
	}
	if !ok || rest == "" {
		return "expected an absolute http(s) URL"
	}
	for _, r := range rest {
		if r < 0x80 && strings.ContainsRune("\"'<>\\^`{|}", r) {
			return "URL contains a character that must be percent-encoded"
		}
		if reWhitespace.MatchString(string(r)) {
			return "URL contains whitespace"
		}
	}
	return ""
}

// The named shapes of §4.1.
var (
	Timestamp   = Re(reTimestamp, "expected a UTC timestamp YYYY-MM-DDTHH:MM:SSZ")
	Date        = Re(reDate, "expected a date YYYY-MM-DD")
	MediaType   = MaxLen(MaxMediaType, Re(reMediaType, "expected a lowercase type/subtype"))
	Extractor   = MaxLen(MaxExtractor, Re(reExtractor, "expected a tool name at a version"))
	ModelID     = Re(reModelID, "expected a model id")
	Semver      = Re(reSemver, "expected a semantic version")
	KeyID       = Re(reKeyID, "expected a key id eb-<purpose>-<name>")
	ReceiptID   = Re(reReceiptID, "expected a receipt id eb_ plus 16 characters")
	DOI         = MaxLen(MaxDOI, Re(reDOI, "expected a DOI"))
	PMID        = Re(rePMID, "expected a PMID of 1 to 9 digits")
	CaseCite    = MaxLen(MaxCaseCite, Re(reCase, "expected a case citation: volume, reporter, page"))
	RetrieverID = Re(reRetrieverID, "expected a retriever id")
	Vantage     = Re(reVantage, "expected a vantage name")
	ArchiveJob  = Re(reArchiveJob, "expected an archive job id")
	Domain      = MaxLen(MaxDomain, Re(reDomain, "expected a registrable host"))
	// PubKey and SigB64 are canonical base64 (§3): the shape and the strict decode together allow
	// exactly one spelling of a key or signature.
	PubKey Shape = func(s string) string {
		if _, err := DecodeKey(s); err != nil {
			return err.Error()
		}
		return ""
	}
	SigB64 Shape = func(s string) string {
		if _, err := DecodeSignature(s); err != nil {
			return err.Error()
		}
		return ""
	}
)

// The strict decoder refuses non-zero trailing bits; the shape regexes refuse everything outside
// the standard alphabet and exact padding, newlines included.
var strictB64 = base64.StdEncoding.Strict()

// DecodeKey returns the 32 raw bytes of a pubkey-b64.
func DecodeKey(b64 string) ([]byte, error) {
	if !rePubKey.MatchString(b64) {
		return nil, errors.New("expected base64 of 32 raw bytes")
	}
	raw, err := strictB64.DecodeString(b64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("public key is not canonical base64 of 32 bytes")
	}
	return raw, nil
}

// DecodeSignature returns the 64 raw bytes of a sig-b64.
func DecodeSignature(b64 string) ([]byte, error) {
	if !reSig.MatchString(b64) {
		return nil, errors.New("expected base64 of 64 raw bytes")
	}
	raw, err := strictB64.DecodeString(b64)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, errors.New("signature is not canonical base64 of 64 bytes")
	}
	return raw, nil
}

// ── validator ─────────────────────────────────────────────────────────────

// Validator keeps the first error; every getter after that is inert and returns zero values,
// so a schema function reads as straight-line code.
type Validator struct {
	err *Error
}

// Fail records the first error.
func (v *Validator) Fail(path, msg string) {
	if v.err == nil {
		v.err = &Error{Path: path, Msg: msg}
	}
}

// Err is the first error, or nil.
func (v *Validator) Err() *Error { return v.err }

// Object is one strict object under validation.
type Object struct {
	v    *Validator
	path string
	val  *canonical.Value
	seen map[string]bool
}

// Object starts validating val as a strict object at path.
func (v *Validator) Object(path string, val *canonical.Value) *Object {
	o := &Object{v: v, path: path}
	if v.err != nil {
		return o
	}
	if val == nil {
		v.Fail(path, "missing member")
		return o
	}
	if val.Kind != canonical.Object {
		v.Fail(path, "expected an object, got "+val.Kind.String())
		return o
	}
	o.val = val
	o.seen = map[string]bool{}
	return o
}

// Member marks name as known and returns its path and value; a missing member is an error.
func (o *Object) Member(name string) (string, *canonical.Value) {
	path := o.path + "." + name
	if o.val == nil || o.v.err != nil {
		return path, nil
	}
	o.seen[name] = true
	m := o.val.Get(name)
	if m == nil {
		o.v.Fail(path, "missing member")
	}
	return path, m
}

// Optional is Member for a member that may be absent: no error when it is missing.
func (o *Object) Optional(name string) (string, *canonical.Value) {
	path := o.path + "." + name
	if o.val == nil || o.v.err != nil {
		return path, nil
	}
	o.seen[name] = true
	return path, o.val.Get(name)
}

// Done reports the first unknown member.
func (o *Object) Done() {
	if o.val == nil || o.v.err != nil {
		return
	}
	for _, m := range o.val.Members {
		if !o.seen[m.Key] {
			o.v.Fail(o.path+"."+m.Key, "unknown member")
			return
		}
	}
}

// Str is a required string member of the given shape.
func (o *Object) Str(name string, s Shape) string {
	path, m := o.Member(name)
	if m == nil {
		return ""
	}
	if m.Kind != canonical.String {
		o.v.Fail(path, "expected a string, got "+m.Kind.String())
		return ""
	}
	if why := s(m.Str); why != "" {
		o.v.Fail(path, why)
	}
	return m.Str
}

// StrOrNull is a string-or-null member.
func (o *Object) StrOrNull(name string, s Shape) *string {
	path, m := o.Member(name)
	if m == nil || m.Kind == canonical.Null {
		return nil
	}
	if m.Kind != canonical.String {
		o.v.Fail(path, "expected a string or null, got "+m.Kind.String())
		return nil
	}
	if why := s(m.Str); why != "" {
		o.v.Fail(path, why)
	}
	out := m.Str
	return &out
}

// Literal is a member that must be exactly want.
func (o *Object) Literal(name, want string) string {
	path, m := o.Member(name)
	if m == nil {
		return ""
	}
	if m.Kind != canonical.String || m.Str != want {
		o.v.Fail(path, "expected the literal "+strconv.Quote(want))
		return ""
	}
	return m.Str
}

// Enum is a member that must be one of allowed.
func (o *Object) Enum(name string, allowed ...string) string {
	path, m := o.Member(name)
	if m == nil {
		return ""
	}
	if m.Kind == canonical.String {
		for _, a := range allowed {
			if m.Str == a {
				return m.Str
			}
		}
	}
	o.v.Fail(path, "expected one of "+strings.Join(allowed, ", "))
	return ""
}

// EnumOrNull is Enum for a nullable member.
func (o *Object) EnumOrNull(name string, allowed ...string) *string {
	_, m := o.Member(name)
	if m == nil || m.Kind == canonical.Null {
		return nil
	}
	s := o.Enum(name, allowed...)
	if o.v.err != nil {
		return nil
	}
	return &s
}

// Integer checks that m is an integer within [min, max].
func Integer(v *Validator, path string, m *canonical.Value, min, max int64) int64 {
	if m.Kind != canonical.Number {
		v.Fail(path, "expected an integer, got "+m.Kind.String())
		return 0
	}
	if !m.IsInt {
		v.Fail(path, "non-integer number")
		return 0
	}
	if m.Int < min || m.Int > max {
		v.Fail(path, "expected an integer from "+strconv.FormatInt(min, 10)+" to "+strconv.FormatInt(max, 10))
		return 0
	}
	return m.Int
}

// Int is a required integer member within [min, max].
func (o *Object) Int(name string, min, max int64) int64 {
	path, m := o.Member(name)
	if m == nil {
		return 0
	}
	return Integer(o.v, path, m, min, max)
}

// IntOrNull is an integer-or-null member.
func (o *Object) IntOrNull(name string, min, max int64) *int64 {
	path, m := o.Member(name)
	if m == nil || m.Kind == canonical.Null {
		return nil
	}
	n := Integer(o.v, path, m, min, max)
	if o.v.err != nil {
		return nil
	}
	return &n
}

// LiteralInt is a member that must be exactly the integer want.
func (o *Object) LiteralInt(name string, want int64) int64 {
	path, m := o.Member(name)
	if m == nil {
		return 0
	}
	if m.Kind != canonical.Number || !m.IsInt || m.Int != want {
		o.v.Fail(path, "expected the literal "+strconv.FormatInt(want, 10))
		return 0
	}
	return m.Int
}

// Boolean is a required boolean member.
func (o *Object) Boolean(name string) bool {
	path, m := o.Member(name)
	if m == nil {
		return false
	}
	if m.Kind != canonical.Bool {
		o.v.Fail(path, "expected a boolean, got "+m.Kind.String())
		return false
	}
	return m.Bool
}

// Null is a member that must be the literal null.
func (o *Object) Null(name string) {
	path, m := o.Member(name)
	if m == nil {
		return
	}
	if m.Kind != canonical.Null {
		o.v.Fail(path, "expected the literal null")
	}
}

// Array is a required array member of at most max entries.
func (o *Object) Array(name string, max int) (string, []*canonical.Value) {
	path, m := o.Member(name)
	if m == nil {
		return path, nil
	}
	if m.Kind != canonical.Array {
		o.v.Fail(path, "expected an array, got "+m.Kind.String())
		return path, nil
	}
	if len(m.Array) > max {
		o.v.Fail(path, "more than "+strconv.Itoa(max)+" entries")
		return path, nil
	}
	return path, m.Array
}

// Obj is a required object member.
func (o *Object) Obj(name string) *Object {
	path, m := o.Member(name)
	if m == nil {
		return &Object{v: o.v, path: path}
	}
	return o.v.Object(path, m)
}

// ObjOrNull is an object-or-null member; nil for null.
func (o *Object) ObjOrNull(name string) *Object {
	path, m := o.Member(name)
	if m == nil || m.Kind == canonical.Null {
		return nil
	}
	return o.v.Object(path, m)
}

func spanOf(v *Validator, path string, m *canonical.Value) [2]int64 {
	var out [2]int64
	if m.Kind != canonical.Array || len(m.Array) != 2 {
		v.Fail(path, "expected a span [start, end]")
		return out
	}
	out[0] = Integer(v, path+"[0]", m.Array[0], 0, canonical.MaxSafeInteger)
	out[1] = Integer(v, path+"[1]", m.Array[1], 0, canonical.MaxSafeInteger)
	if v.err == nil && out[0] > out[1] {
		v.Fail(path, "expected span start <= end")
	}
	return out
}

// Span is a required [start, end] member with 0 <= start <= end.
func (o *Object) Span(name string) [2]int64 {
	path, m := o.Member(name)
	if m == nil {
		return [2]int64{}
	}
	return spanOf(o.v, path, m)
}

// SpanOrNull is a span-or-null member.
func (o *Object) SpanOrNull(name string) *[2]int64 {
	path, m := o.Member(name)
	if m == nil || m.Kind == canonical.Null {
		return nil
	}
	s := spanOf(o.v, path, m)
	if o.v.err != nil {
		return nil
	}
	return &s
}

// ── the compatibility rule (§15) ──────────────────────────────────────────

// EnumOr is Enum for a member the compatibility rule lets a body omit (spec §15): def when it is
// absent, the usual check when it is present.
func (o *Object) EnumOr(name, def string, allowed ...string) string {
	if _, m := o.Optional(name); m == nil {
		return def
	}
	return o.Enum(name, allowed...)
}

// IntOr is Int for a member the compatibility rule lets a body omit: def when it is absent.
func (o *Object) IntOr(name string, def, min, max int64) int64 {
	if _, m := o.Optional(name); m == nil {
		return def
	}
	return o.Int(name, min, max)
}

// StrOrNullOr is StrOrNull for a member the compatibility rule lets a body omit: def when it is
// absent, nil when it is null.
func (o *Object) StrOrNullOr(name, def string, s Shape) *string {
	if _, m := o.Optional(name); m == nil {
		return &def
	}
	return o.StrOrNull(name, s)
}

var reSemverTriple = regexp.MustCompile(`\A([0-9]+)\.([0-9]+)\.([0-9]+)`)

// SemverBefore reports whether version is below major.minor.patch on the numeric triple alone —
// a pre-release or build suffix is ignored, so 0.1.0-rc.1 is before 0.2.0 and 0.2.0-rc.1 is not.
// A string that is not a semver is not before anything: the Semver shape refuses it on its own.
// Each component is read as a signed 64-bit integer, and one that does not fit makes the version
// not before anything, whichever component it is — the issuer's comparator reads the same limit.
func SemverBefore(version string, major, minor, patch int64) bool {
	m := reSemverTriple.FindStringSubmatch(version)
	if m == nil {
		return false
	}
	var got [3]int64
	for i := range got {
		n, err := strconv.ParseInt(m[i+1], 10, 64)
		if err != nil {
			return false
		}
		got[i] = n
	}
	want := [3]int64{major, minor, patch}
	for i := range got {
		if got[i] != want[i] {
			return got[i] < want[i]
		}
	}
	return false
}

// Path is the object's path.
func (o *Object) Path() string { return o.path }

// Validator is the validator this object reports to.
func (o *Object) Validator() *Validator { return o.v }
