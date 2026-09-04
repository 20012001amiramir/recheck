// Package canonical reads JSON strictly and writes it in the canonical form of spec/RECEIPT.md §1:
// RFC 8785 restricted to null, booleans, safe integers, strings, arrays and objects.
//
// It has its own parser because the standard library's is too forgiving for a verifier: it keeps
// the last of two duplicate keys, turns a lone surrogate or an invalid UTF-8 byte into U+FFFD, and
// reports no path. Every hash in the product is over canonical bytes, so a parser that quietly
// repairs its input would let two different documents hash alike.
package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxSafeInteger is 2^53 − 1, the largest magnitude an integer in a receipt may have (spec §0).
const MaxSafeInteger = 1<<53 - 1

const maxDepth = 1024

// Kind is the JSON type of a Value.
type Kind uint8

// The six JSON kinds.
const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

func (k Kind) String() string {
	switch k {
	case Null:
		return "null"
	case Bool:
		return "boolean"
	case Number:
		return "number"
	case String:
		return "string"
	case Array:
		return "array"
	case Object:
		return "object"
	}
	return "unknown"
}

// Value is a parsed JSON value. Object members keep their source order (canonical output sorts
// them); Offset and End are byte positions in the source, which the tamper report uses.
type Value struct {
	Kind Kind
	Bool bool
	// Int is the value of an integer number; IsInt is false for a number whose value is not a
	// safe integer (a fraction, an exponent that does not resolve to a whole number, |n| > 2^53−1),
	// which the canonical form refuses. Literal is the number token as written.
	Int     int64
	IsInt   bool
	Literal string
	Str     string
	Array   []*Value
	Members []Member
	Offset  int
	End     int
}

// Member is one object member in source order.
type Member struct {
	Key       string
	KeyOffset int
	Value     *Value
}

// Get returns the member named key, or nil when v is not an object or has no such member.
func (v *Value) Get(key string) *Value {
	if v == nil || v.Kind != Object {
		return nil
	}
	for _, m := range v.Members {
		if m.Key == key {
			return m.Value
		}
	}
	return nil
}

// Error reports JSON that does not parse or a value the canonical profile refuses. Path uses the
// spec's notation: $ for the root, $.key for a member, $[3] for an element.
type Error struct {
	Msg    string
	Path   string
	Offset int // byte offset in the source; -1 when the value did not come from text
}

func (e *Error) Error() string { return e.Msg + " at " + e.Path }

// Parse reads one JSON text. It refuses a byte-order mark, trailing content, duplicate object
// keys, unpaired surrogates (escaped or raw), invalid UTF-8 and raw control characters. Numbers
// of any JSON shape are read; whether their value is a safe integer is recorded in IsInt and
// enforced by Canonicalize, so a document with a fraction in it still parses and can be reported
// on by path.
func Parse(data []byte) (*Value, error) {
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, &Error{Msg: "byte-order mark is not JSON", Path: "$", Offset: 0}
	}
	p := &parser{data: data}
	p.skipWS()
	if p.pos >= len(data) {
		return nil, &Error{Msg: "empty input", Path: "$", Offset: p.pos}
	}
	v, err := p.value("$")
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(data) {
		return nil, p.fail("$", "unexpected content after the value")
	}
	return v, nil
}

type parser struct {
	data  []byte
	pos   int
	depth int
}

func (p *parser) fail(path, msg string) *Error {
	return &Error{Msg: msg, Path: path, Offset: p.pos}
}

func (p *parser) skipWS() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) peek() int {
	if p.pos < len(p.data) {
		return int(p.data[p.pos])
	}
	return -1
}

func (p *parser) value(path string) (*Value, error) {
	if p.pos >= len(p.data) {
		return nil, p.fail(path, "unexpected end of input")
	}
	start := p.pos
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.object(path)
	case c == '[':
		return p.array(path)
	case c == '"':
		s, err := p.str(path)
		if err != nil {
			return nil, err
		}
		return &Value{Kind: String, Str: s, Offset: start, End: p.pos}, nil
	case c == 't':
		return p.literal(path, "true", &Value{Kind: Bool, Bool: true})
	case c == 'f':
		return p.literal(path, "false", &Value{Kind: Bool})
	case c == 'n':
		return p.literal(path, "null", &Value{Kind: Null})
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number(path)
	default:
		return nil, p.fail(path, fmt.Sprintf("unexpected character %q", c))
	}
}

func (p *parser) literal(path, word string, v *Value) (*Value, error) {
	if !bytes.HasPrefix(p.data[p.pos:], []byte(word)) {
		return nil, p.fail(path, "invalid literal")
	}
	v.Offset = p.pos
	p.pos += len(word)
	v.End = p.pos
	return v, nil
}

func (p *parser) number(path string) (*Value, error) {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
	}
	if p.pos >= len(p.data) {
		return nil, p.fail(path, "invalid number")
	}
	switch c := p.data[p.pos]; {
	case c == '0':
		p.pos++
	case c >= '1' && c <= '9':
		p.digits()
	default:
		return nil, p.fail(path, "invalid number")
	}
	if p.peek() == '.' {
		p.pos++
		if p.digits() == 0 {
			return nil, p.fail(path, "invalid number")
		}
	}
	if c := p.peek(); c == 'e' || c == 'E' {
		p.pos++
		if c := p.peek(); c == '+' || c == '-' {
			p.pos++
		}
		if p.digits() == 0 {
			return nil, p.fail(path, "invalid number")
		}
	}
	lit := string(p.data[start:p.pos])
	v := &Value{Kind: Number, Literal: lit, Offset: start, End: p.pos}
	// The rule is about values, not tokens (spec §1.4): 812004.0 and 8.12004e5 are the integer
	// 812004. A double that is integral and within ±(2^53 − 1) is an integer; anything else is not.
	f, err := strconv.ParseFloat(lit, 64)
	if err == nil && !math.IsInf(f, 0) && f == math.Trunc(f) && math.Abs(f) <= MaxSafeInteger {
		v.IsInt = true
		v.Int = int64(f)
	}
	return v, nil
}

func (p *parser) digits() int {
	n := 0
	for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
		p.pos++
		n++
	}
	return n
}

func (p *parser) hex4() (uint16, bool) {
	if p.pos+4 > len(p.data) {
		return 0, false
	}
	var u uint16
	for i := 0; i < 4; i++ {
		c := p.data[p.pos+i]
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, false
		}
		u = u<<4 | uint16(d)
	}
	p.pos += 4
	return u, true
}

// str reads a string token starting at the opening quote.
func (p *parser) str(path string) (string, error) {
	p.pos++
	var b []byte
	for {
		if p.pos >= len(p.data) {
			return "", p.fail(path, "unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return string(b), nil
		case c == '\\':
			p.pos++
			if p.pos >= len(p.data) {
				return "", p.fail(path, "unterminated string")
			}
			e := p.data[p.pos]
			p.pos++
			switch e {
			case '"', '\\', '/':
				b = append(b, e)
			case 'b':
				b = append(b, '\b')
			case 'f':
				b = append(b, '\f')
			case 'n':
				b = append(b, '\n')
			case 'r':
				b = append(b, '\r')
			case 't':
				b = append(b, '\t')
			case 'u':
				u, ok := p.hex4()
				if !ok {
					return "", p.fail(path, "invalid \\u escape")
				}
				switch {
				case u >= 0xDC00 && u <= 0xDFFF:
					return "", p.fail(path, "unpaired surrogate")
				case u >= 0xD800 && u <= 0xDBFF:
					if p.pos+1 >= len(p.data) || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
						return "", p.fail(path, "unpaired surrogate")
					}
					p.pos += 2
					lo, ok := p.hex4()
					if !ok {
						return "", p.fail(path, "invalid \\u escape")
					}
					if lo < 0xDC00 || lo > 0xDFFF {
						return "", p.fail(path, "unpaired surrogate")
					}
					b = utf8.AppendRune(b, utf16.DecodeRune(rune(u), rune(lo)))
				default:
					b = utf8.AppendRune(b, rune(u))
				}
			default:
				return "", p.fail(path, fmt.Sprintf("invalid escape \\%c", e))
			}
		case c < 0x20:
			return "", p.fail(path, "control character in string")
		case c < utf8.RuneSelf:
			b = append(b, c)
			p.pos++
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size == 1 {
				// ED A0..BF is how a surrogate would look if someone wrote it into UTF-8.
				if c == 0xED && p.pos+1 < len(p.data) && p.data[p.pos+1] >= 0xA0 {
					return "", p.fail(path, "unpaired surrogate")
				}
				return "", p.fail(path, "invalid UTF-8")
			}
			b = append(b, p.data[p.pos:p.pos+size]...)
			p.pos += size
		}
	}
}

func (p *parser) enter(path string) error {
	p.depth++
	if p.depth > maxDepth {
		return p.fail(path, fmt.Sprintf("nesting deeper than %d levels", maxDepth))
	}
	return nil
}

func (p *parser) object(path string) (*Value, error) {
	if err := p.enter(path); err != nil {
		return nil, err
	}
	defer func() { p.depth-- }()
	v := &Value{Kind: Object, Offset: p.pos}
	p.pos++
	p.skipWS()
	if p.peek() == '}' {
		p.pos++
		v.End = p.pos
		return v, nil
	}
	seen := map[string]bool{}
	for {
		p.skipWS()
		if p.peek() != '"' {
			return nil, p.fail(path, "expected a string key")
		}
		keyOffset := p.pos
		key, err := p.str(path)
		if err != nil {
			return nil, err
		}
		if seen[key] {
			return nil, &Error{Msg: fmt.Sprintf("duplicate key %q", key), Path: path, Offset: keyOffset}
		}
		seen[key] = true
		p.skipWS()
		if p.peek() != ':' {
			return nil, p.fail(path, "expected ':' after a key")
		}
		p.pos++
		p.skipWS()
		child, err := p.value(path + "." + key)
		if err != nil {
			return nil, err
		}
		v.Members = append(v.Members, Member{Key: key, KeyOffset: keyOffset, Value: child})
		p.skipWS()
		switch p.peek() {
		case ',':
			p.pos++
		case '}':
			p.pos++
			v.End = p.pos
			return v, nil
		default:
			return nil, p.fail(path, "expected ',' or '}'")
		}
	}
}

func (p *parser) array(path string) (*Value, error) {
	if err := p.enter(path); err != nil {
		return nil, err
	}
	defer func() { p.depth-- }()
	v := &Value{Kind: Array, Offset: p.pos}
	p.pos++
	p.skipWS()
	if p.peek() == ']' {
		p.pos++
		v.End = p.pos
		return v, nil
	}
	for {
		p.skipWS()
		child, err := p.value(path + "[" + strconv.Itoa(len(v.Array)) + "]")
		if err != nil {
			return nil, err
		}
		v.Array = append(v.Array, child)
		p.skipWS()
		switch p.peek() {
		case ',':
			p.pos++
		case ']':
			p.pos++
			v.End = p.pos
			return v, nil
		default:
			return nil, p.fail(path, "expected ',' or ']'")
		}
	}
}

// ── serialisation ─────────────────────────────────────────────────────────

// Canonicalize returns the canonical bytes of v (spec §1). v is a *Value from Parse or one of the
// Go values nil, bool, string, int, int64, float64 (whole and within ±(2^53 − 1)), []any and
// map[string]any. Anything else, a non-integer number, or a string that is not valid UTF-8 is an
// *Error naming the path.
func Canonicalize(v any) ([]byte, error) {
	e := &encoder{}
	if err := e.encode(v, "$"); err != nil {
		return nil, err
	}
	return e.buf.Bytes(), nil
}

// Pretty renders v as indented JSON (two spaces) with the canonical escaping, so parsing the
// output gives back the same value. A parsed Value keeps its source member order; a map is sorted.
func Pretty(v any) ([]byte, error) {
	e := &encoder{pretty: true}
	if err := e.encode(v, "$"); err != nil {
		return nil, err
	}
	e.buf.WriteByte('\n')
	return e.buf.Bytes(), nil
}

// Body returns v without its top-level self_hash and signatures members (spec §2). v must be an
// object: a *Value or a map[string]any.
func Body(v any) (any, error) {
	switch x := v.(type) {
	case *Value:
		if x == nil || x.Kind != Object {
			return nil, &Error{Msg: "self-hash needs an object", Path: "$", Offset: -1}
		}
		out := &Value{Kind: Object, Offset: x.Offset, End: x.End}
		for _, m := range x.Members {
			if m.Key == "self_hash" || m.Key == "signatures" {
				continue
			}
			out.Members = append(out.Members, m)
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if k == "self_hash" || k == "signatures" {
				continue
			}
			out[k] = val
		}
		return out, nil
	}
	return nil, &Error{Msg: "self-hash needs an object", Path: "$", Offset: -1}
}

// SelfHash is hex(sha256(canonical(Body(v)))) — spec §2.
func SelfHash(v any) (string, error) {
	body, err := Body(v)
	if err != nil {
		return "", err
	}
	c, err := Canonicalize(body)
	if err != nil {
		return "", err
	}
	return Sha256Hex(c), nil
}

// Sha256Hex is the lowercase hex SHA-256 of b.
func Sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type encoder struct {
	buf    bytes.Buffer
	pretty bool
	level  int
}

func (e *encoder) newline() {
	if !e.pretty {
		return
	}
	e.buf.WriteByte('\n')
	for i := 0; i < e.level; i++ {
		e.buf.WriteString("  ")
	}
}

func (e *encoder) colon() {
	if e.pretty {
		e.buf.WriteString(": ")
	} else {
		e.buf.WriteByte(':')
	}
}

func (e *encoder) encode(v any, path string) error {
	switch x := v.(type) {
	case *Value:
		return e.value(x, path)
	case nil:
		e.buf.WriteString("null")
	case bool:
		if x {
			e.buf.WriteString("true")
		} else {
			e.buf.WriteString("false")
		}
	case string:
		if !utf8.ValidString(x) {
			return &Error{Msg: "invalid UTF-8", Path: path, Offset: -1}
		}
		writeString(&e.buf, x)
	case int:
		return e.integer(int64(x), path)
	case int64:
		return e.integer(x, path)
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) || x != math.Trunc(x) || math.Abs(x) > MaxSafeInteger {
			return &Error{Msg: "non-integer number", Path: path, Offset: -1}
		}
		return e.integer(int64(x), path)
	case []any:
		e.buf.WriteByte('[')
		e.level++
		for i, item := range x {
			if i > 0 {
				e.buf.WriteByte(',')
			}
			e.newline()
			if err := e.encode(item, path+"["+strconv.Itoa(i)+"]"); err != nil {
				return err
			}
		}
		e.level--
		if len(x) > 0 {
			e.newline()
		}
		e.buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			if !utf8.ValidString(k) {
				return &Error{Msg: "invalid UTF-8 in key", Path: path, Offset: -1}
			}
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		e.buf.WriteByte('{')
		e.level++
		for i, k := range keys {
			if i > 0 {
				e.buf.WriteByte(',')
			}
			e.newline()
			writeString(&e.buf, k)
			e.colon()
			if err := e.encode(x[k], path+"."+k); err != nil {
				return err
			}
		}
		e.level--
		if len(keys) > 0 {
			e.newline()
		}
		e.buf.WriteByte('}')
	default:
		return &Error{Msg: "unsupported value", Path: path, Offset: -1}
	}
	return nil
}

func (e *encoder) integer(n int64, path string) error {
	if n > MaxSafeInteger || n < -MaxSafeInteger {
		return &Error{Msg: "non-integer number", Path: path, Offset: -1}
	}
	e.buf.WriteString(strconv.FormatInt(n, 10))
	return nil
}

func (e *encoder) value(v *Value, path string) error {
	if v == nil {
		return &Error{Msg: "unsupported value", Path: path, Offset: -1}
	}
	switch v.Kind {
	case Null:
		e.buf.WriteString("null")
	case Bool:
		if v.Bool {
			e.buf.WriteString("true")
		} else {
			e.buf.WriteString("false")
		}
	case Number:
		if !v.IsInt {
			return &Error{Msg: "non-integer number", Path: path, Offset: v.Offset}
		}
		return e.integer(v.Int, path)
	case String:
		writeString(&e.buf, v.Str)
	case Array:
		e.buf.WriteByte('[')
		e.level++
		for i, item := range v.Array {
			if i > 0 {
				e.buf.WriteByte(',')
			}
			e.newline()
			if err := e.value(item, path+"["+strconv.Itoa(i)+"]"); err != nil {
				return err
			}
		}
		e.level--
		if len(v.Array) > 0 {
			e.newline()
		}
		e.buf.WriteByte(']')
	case Object:
		order := make([]int, len(v.Members))
		for i := range order {
			order[i] = i
		}
		if !e.pretty {
			sort.SliceStable(order, func(i, j int) bool {
				return lessUTF16(v.Members[order[i]].Key, v.Members[order[j]].Key)
			})
		}
		e.buf.WriteByte('{')
		e.level++
		for i, idx := range order {
			m := v.Members[idx]
			if i > 0 {
				e.buf.WriteByte(',')
			}
			e.newline()
			writeString(&e.buf, m.Key)
			e.colon()
			if err := e.value(m.Value, path+"."+m.Key); err != nil {
				return err
			}
		}
		e.level--
		if len(order) > 0 {
			e.newline()
		}
		e.buf.WriteByte('}')
	default:
		return &Error{Msg: "unsupported value", Path: path, Offset: -1}
	}
	return nil
}

// writeString applies the spec §1.5 escape table to a valid UTF-8 string.
func writeString(b *bytes.Buffer, s string) {
	const hexDigits = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			if c < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hexDigits[c>>4])
				b.WriteByte(hexDigits[c&0xF])
			} else {
				// Everything else, non-ASCII included, is the code unit itself as UTF-8.
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
}

// lessUTF16 orders keys by UTF-16 code unit (spec §1.7): a surrogate pair sorts by its first unit,
// so a key starting with U+1F600 lands between U+D7FF and U+E000.
func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}
