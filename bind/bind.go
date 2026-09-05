// Package bind re-proves that a receipt was issued for a document: it recomputes the document's
// sha256 and every claim and quote HMAC from the creator's binding bundle (receipt §4.5).
//
// The bundle is what the issuer hands the creator as binding.json:
//
//	{ "binding_key": <hex or base64 of 32 bytes>, "document_sha256": hex64,
//	  "claims": [ { "n": 1, "claim_text": "…", "quote": "…" | null }, … ] }
//
// claim_hmac is HMAC-SHA256(binding_key, "claim:" + norm(claim_text)) and quote_hmac is the same
// with "quote:", where norm is the engine's norm@1 text normalization (Norm below). The value of
// an unsupported locator is an HMAC of the citation string too, but the bundle does not carry
// that string, so it is not checked here.
package bind

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/20012001amiramir/recheck/canonical"
	"github.com/20012001amiramir/recheck/receipt"
)

// Bundle is a parsed binding.json.
type Bundle struct {
	BindingKey     []byte
	DocumentSHA256 string
	Claims         []Claim
}

// Claim is one entry of the bundle.
type Claim struct {
	N         int64
	ClaimText string
	Quote     *string
}

// ParseBundle reads binding.json. binding_key may be hex or base64; members the check does not
// need are ignored.
//
// The bundle is read leniently. Nothing in it is hashed or canonicalized — the hashes are the
// receipt's, and the bundle only supplies the text behind them — so the strict parser's refusal
// of a lone surrogate would throw the whole file out over one character of one claim, which the
// engine's JSON.stringify is entitled to emit. A claim whose text does not re-derive its HMAC is
// reported as that claim failing, which is the answer the reader came for either way.
func ParseBundle(data []byte) (*Bundle, error) {
	raw, err := canonical.ParseLenient(data)
	if err != nil {
		return nil, fmt.Errorf("binding.json: %w", err)
	}
	if raw.Kind != canonical.Object {
		return nil, errors.New("binding.json: expected an object")
	}
	b := &Bundle{}
	key := raw.Get("binding_key")
	if key == nil || key.Kind != canonical.String {
		return nil, errors.New("binding.json: binding_key must be a string")
	}
	b.BindingKey, err = decodeKey(key.Str)
	if err != nil {
		return nil, fmt.Errorf("binding.json: binding_key: %w", err)
	}
	if d := raw.Get("document_sha256"); d != nil && d.Kind == canonical.String {
		if !receipt.Hex64Shape(d.Str) {
			return nil, errors.New("binding.json: document_sha256 must be hex64")
		}
		b.DocumentSHA256 = d.Str
	}
	claims := raw.Get("claims")
	if claims == nil || claims.Kind != canonical.Array {
		return nil, errors.New("binding.json: claims must be an array")
	}
	for i, c := range claims.Array {
		n := c.Get("n")
		text := c.Get("claim_text")
		if n == nil || n.Kind != canonical.Number || !n.IsInt || n.Int < 1 || text == nil || text.Kind != canonical.String {
			return nil, fmt.Errorf("binding.json: claims[%d] needs an integer n and a claim_text", i)
		}
		entry := Claim{N: n.Int, ClaimText: text.Str}
		if q := c.Get("quote"); q != nil && q.Kind == canonical.String {
			s := q.Str
			entry.Quote = &s
		}
		b.Claims = append(b.Claims, entry)
	}
	return b, nil
}

func decodeKey(s string) ([]byte, error) {
	if len(s) == 64 {
		if raw, err := hex.DecodeString(s); err == nil {
			return raw, nil
		}
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil && len(raw) == 32 {
		return raw, nil
	}
	return nil, errors.New("expected 32 bytes as hex or base64")
}

// Norm is the engine's norm@1 text normalization: curly quotes to straight, every dash to `-`,
// the Unicode spaces to a space, whitespace runs collapsed to one space and trimmed, then
// lowercased character by character as ECMAScript's toLowerCase does (a character above U+FFFF
// is left alone, since the engine lowercases UTF-16 code units one at a time).
func Norm(s string) string {
	var out []rune
	pendingSpace := false
	for _, r := range s {
		for _, c := range normChar(r) {
			if isJSWhitespace(c) {
				pendingSpace = len(out) > 0
				continue
			}
			if pendingSpace {
				out = append(out, ' ')
				pendingSpace = false
			}
			out = append(out, c)
		}
	}
	return string(out)
}

func normChar(r rune) string {
	switch r {
	case 0x2018, 0x2019, 0x201A, 0x201B, 0x2032, 0x0060, 0x00B4:
		return "'"
	case 0x201C, 0x201D, 0x201E, 0x201F, 0x2033, 0x00AB, 0x00BB:
		return "\""
	case 0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212:
		return "-"
	case 0x00A0, 0x202F, 0x205F, 0x3000:
		return " "
	case 0x0130:
		// The one unconditional full lowercase mapping: İ becomes i followed by U+0307.
		return "i̇"
	}
	if r >= 0x2000 && r <= 0x200B {
		return " "
	}
	if r >= 0x10000 {
		return string(r)
	}
	return string(unicode.ToLower(r))
}

func isJSWhitespace(r rune) bool {
	switch r {
	case 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}

func mac(key []byte, prefix, text string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(prefix + Norm(text)))
	return hex.EncodeToString(m.Sum(nil))
}

// ClaimHMAC is hex(HMAC-SHA256(key, "claim:" + Norm(text))).
func ClaimHMAC(key []byte, text string) string { return mac(key, "claim:", text) }

// QuoteHMAC is hex(HMAC-SHA256(key, "quote:" + Norm(text))).
func QuoteHMAC(key []byte, text string) string { return mac(key, "quote:", text) }

// Check names of the bind command.
var CheckNames = []string{"document_sha256", "binding_key", "claims"}

// Check re-derives the document hash and every claim and quote HMAC. document is the uploaded
// file's bytes (or the pasted text's UTF-8).
func Check(rec *receipt.Receipt, b *Bundle, document []byte) []receipt.Check {
	var checks []receipt.Check
	add := func(name, status, detail string) {
		checks = append(checks, receipt.Check{Name: name, Status: status, Detail: detail})
	}

	docHash := canonical.Sha256Hex(document)
	switch {
	case docHash != rec.Document.SHA256:
		add("document_sha256", receipt.Fail, "the document hashes to "+docHash+", the receipt says "+rec.Document.SHA256)
	case b.DocumentSHA256 != "" && b.DocumentSHA256 != rec.Document.SHA256:
		add("document_sha256", receipt.Fail, "binding.json is for document "+b.DocumentSHA256+", the receipt is for "+rec.Document.SHA256)
	default:
		add("document_sha256", receipt.Pass, docHash+" ("+strconv.Itoa(len(document))+" bytes)")
	}

	keyHash := canonical.Sha256Hex(b.BindingKey)
	if keyHash == rec.Binding.KeySHA256 {
		add("binding_key", receipt.Pass, "sha256 of the binding key is the receipt's key_sha256")
	} else {
		add("binding_key", receipt.Fail, "the binding key hashes to "+keyHash+", the receipt says "+rec.Binding.KeySHA256)
	}

	byN := map[int64]Claim{}
	for _, c := range b.Claims {
		byN[c.N] = c
	}
	var problems []string
	quotes, unsupported := 0, 0
	for _, rc := range rec.Claims {
		bc, ok := byN[rc.N]
		n := strconv.FormatInt(rc.N, 10)
		if !ok {
			problems = append(problems, "claim "+n+" is not in binding.json")
			continue
		}
		if ClaimHMAC(b.BindingKey, bc.ClaimText) != rc.ClaimHMAC {
			problems = append(problems, "claim "+n+": claim_hmac does not match its text")
		}
		switch {
		case rc.QuoteHMAC == nil && bc.Quote == nil:
		case rc.QuoteHMAC == nil:
			problems = append(problems, "claim "+n+": the receipt has no quote but binding.json does")
		case bc.Quote == nil:
			problems = append(problems, "claim "+n+": the receipt has a quote_hmac but binding.json has no quote")
		case QuoteHMAC(b.BindingKey, *bc.Quote) != *rc.QuoteHMAC:
			problems = append(problems, "claim "+n+": quote_hmac does not match its quote")
		default:
			quotes++
		}
		if rc.Locator.Type == "unsupported" {
			unsupported++
		}
	}
	detail := strconv.Itoa(len(rec.Claims)) + " claims and " + strconv.Itoa(quotes) + " quotes re-derived from the binding key"
	if unsupported > 0 {
		detail += "; " + strconv.Itoa(unsupported) + " unsupported-locator value(s) not checked (binding.json carries no citation text)"
	}
	if len(problems) > 0 {
		add("claims", receipt.Fail, strings.Join(problems, "; "))
	} else {
		add("claims", receipt.Pass, detail)
	}
	return checks
}
