package bind_test

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/20012001amiramir/recheck/bind"
	"github.com/20012001amiramir/recheck/canonical"
	"github.com/20012001amiramir/recheck/receipt"
)

func TestNorm(t *testing.T) {
	cases := map[string]string{
		"  Hello, \u201cWorld\u201d  \u2014  it\u2019s\u200bdone ": `hello, "world" - it's done`,
		"A\tB\nC\r\n D":                             "a b c d",
		"\u3000x\u3000":                             "x",
		"a\u00a0b\u2003c\u202fd":                    "a b c d",
		"\u0130stanbul":                             "i\u0307stanbul",
		"\u03a3\u0391\u03a3":                        "\u03c3\u03b1\u03c3",
		"\U00010400 x":                              "\U00010400 x",
		"a\u2010b\u2212c\u2013d\u2015e":             "a-b-c-d-e",
		"\u00abq\u00bb \u201as\u201b \u2032p\u2033": `"q" 's' 'p"`,
		"":                              "",
		"   ":                           "",
		"already normal":                "already normal",
		"x\u00a0y\ufeffz\u1680w\u2028v": "x y z w v",
		"Stra\u00dfe":                   "stra\u00dfe",
		"`back` \u00b4acute\u00b4":      "'back' 'acute'",
	}
	for in, want := range cases {
		if got := bind.Norm(in); got != want {
			t.Errorf("Norm(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHMACRule(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	m := hmac.New(sha256.New, key)
	m.Write([]byte("claim:the sky is blue"))
	if got := bind.ClaimHMAC(key, "  The sky is BLUE "); got != hex.EncodeToString(m.Sum(nil)) {
		t.Errorf("claim hmac %s", got)
	}
	m = hmac.New(sha256.New, key)
	m.Write([]byte("quote:\"blue\""))
	if got := bind.QuoteHMAC(key, "“blue”"); got != hex.EncodeToString(m.Sum(nil)) {
		t.Errorf("quote hmac %s", got)
	}
}

// fixture builds a document, a binding bundle and a receipt sealed for them with the vector key.
func fixture(t *testing.T) (rec *receipt.Receipt, bundleJSON []byte, document []byte, key []byte) {
	t.Helper()
	document = []byte("Q1 report.\n\nRevenue grew 12% (https://www.example.org/reports/2026/q1.pdf).\nThe trial was stopped early [10.1136/bmj.n1234].\nSee also Smith 2019.\n")
	key = bytes32("binding-key")
	texts := []struct {
		text  string
		quote *string
	}{
		{"Revenue grew 12% (https://www.example.org/reports/2026/q1.pdf).", ptr("Revenue grew 12%")},
		{"The trial was stopped early [10.1136/bmj.n1234].", ptr("stopped early")},
		{"See also Smith 2019.", nil},
	}

	data, err := os.ReadFile(filepath.Join("..", "spec", "vectors", "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	vec, err := canonical.ParseLenient(data)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := canonical.Canonicalize(vec.Get("receipt"))
	v, _ := canonical.Parse(body)
	set(v.Get("document"), "sha256", str(canonical.Sha256Hex(document)))
	set(v.Get("document"), "bytes", num(int64(len(document))))
	set(v.Get("binding"), "key_sha256", str(canonical.Sha256Hex(key)))
	bundle := `{"binding_key":"` + hex.EncodeToString(key) + `","document_sha256":"` + canonical.Sha256Hex(document) + `","claims":[`
	for i, c := range v.Get("claims").Array {
		set(c, "claim_hmac", str(bind.ClaimHMAC(key, texts[i].text)))
		bundle += `{"n":` + string(rune('1'+i)) + `,"claim_text":` + jsonString(texts[i].text)
		if texts[i].quote != nil {
			set(c, "quote_hmac", str(bind.QuoteHMAC(key, *texts[i].quote)))
			bundle += `,"quote":` + jsonString(*texts[i].quote)
		} else {
			set(c, "quote_hmac", &canonical.Value{Kind: canonical.Null})
			bundle += `,"quote":null`
		}
		bundle += "}"
		if i < 2 {
			bundle += ","
		}
	}
	bundle += `],"extra_member":"ignored"}`

	set(v, "signatures", &canonical.Value{Kind: canonical.Array})
	selfHash, _ := canonical.SelfHash(v)
	set(v, "self_hash", str(selfHash))
	sig, err := receipt.Sign(fixtureKey(t), selfHash)
	if err != nil {
		t.Fatal(err)
	}
	entry := &canonical.Value{Kind: canonical.Object}
	set(entry, "key_id", str("eb-receipt-test"))
	set(entry, "alg", str("ed25519"))
	set(entry, "sig", str(sig))
	set(entry, "role", str("issuer"))
	set(v, "signatures", &canonical.Value{Kind: canonical.Array, Array: []*canonical.Value{entry}})
	sealed, _ := canonical.Canonicalize(v)
	res := receipt.Verify(sealed, nil)
	if !res.OK() {
		t.Fatalf("fixture receipt does not verify: %v", res.Checks)
	}
	return res.Receipt, []byte(bundle), document, key
}

func TestBind(t *testing.T) {
	rec, bundleJSON, document, key := fixture(t)
	bundle, err := bind.ParseBundle(bundleJSON)
	if err != nil {
		t.Fatal(err)
	}
	if !hmacEqual(bundle.BindingKey, key) || len(bundle.Claims) != 3 || bundle.Claims[2].Quote != nil {
		t.Fatalf("bundle %+v", bundle)
	}
	checks := bind.Check(rec, bundle, document)
	for _, c := range checks {
		if c.Status != receipt.Pass {
			t.Errorf("%s: %s", c.Name, c.Detail)
		}
	}
	if !strings.Contains(checks[2].Detail, "3 claims and 2 quotes") || !strings.Contains(checks[2].Detail, "1 unsupported") {
		t.Errorf("claims detail: %s", checks[2].Detail)
	}

	// One byte of the document changes: the document hash fails, the HMACs still hold.
	altered := append([]byte{}, document...)
	altered[3] ^= 1
	checks = bind.Check(rec, bundle, altered)
	if checks[0].Status != receipt.Fail || checks[1].Status != receipt.Pass || checks[2].Status != receipt.Pass {
		t.Errorf("altered document: %v", checks)
	}

	// A claim text edited in the bundle.
	edited, _ := bind.ParseBundle([]byte(strings.Replace(string(bundleJSON), "grew 12%", "grew 13%", 1)))
	checks = bind.Check(rec, edited, document)
	if checks[2].Status != receipt.Fail || !strings.Contains(checks[2].Detail, "claim 1: claim_hmac") {
		t.Errorf("edited claim: %v", checks)
	}
	// Normalization-only differences do not matter.
	spaced, _ := bind.ParseBundle([]byte(strings.Replace(string(bundleJSON), "grew 12%", "GREW 12%", 1)))
	if checks := bind.Check(rec, spaced, document); checks[2].Status != receipt.Pass {
		t.Errorf("normalized claim: %v", checks)
	}
	// A quote removed, a claim missing, a wrong key.
	noQuote, _ := bind.ParseBundle([]byte(strings.Replace(string(bundleJSON), `"quote":"stopped early"`, `"quote":null`, 1)))
	if checks := bind.Check(rec, noQuote, document); checks[2].Status != receipt.Fail || !strings.Contains(checks[2].Detail, "claim 2") {
		t.Errorf("missing quote: %v", checks)
	}
	fewer, _ := bind.ParseBundle([]byte(strings.Replace(string(bundleJSON), `{"n":3,`, `{"n":4,`, 1)))
	if checks := bind.Check(rec, fewer, document); checks[2].Status != receipt.Fail || !strings.Contains(checks[2].Detail, "claim 3 is not in binding.json") {
		t.Errorf("missing claim: %v", checks)
	}
	wrongKey, _ := bind.ParseBundle([]byte(strings.Replace(string(bundleJSON), hex.EncodeToString(key), base64.StdEncoding.EncodeToString(bytes32("other")), 1)))
	if checks := bind.Check(rec, wrongKey, document); checks[1].Status != receipt.Fail || checks[2].Status != receipt.Fail {
		t.Errorf("wrong key: %v", checks)
	}
	// The key may be base64 too.
	b64, err := bind.ParseBundle([]byte(strings.Replace(string(bundleJSON), hex.EncodeToString(key), base64.StdEncoding.EncodeToString(key), 1)))
	if err != nil || !hmacEqual(b64.BindingKey, key) {
		t.Errorf("base64 key: %v", err)
	}
	// A lone surrogate in a claim text is read rather than refused: the bundle is not hashed, and
	// the engine's JSON.stringify emits one for an unpaired code unit. The claim then simply does
	// not re-derive its HMAC, which is a verdict on that claim, not on the file.
	surrogate, err := bind.ParseBundle([]byte(strings.Replace(string(bundleJSON), "grew 12%", `grew 12% \ud800`, 1)))
	if err != nil {
		t.Errorf("lone surrogate refused: %v", err)
	} else if checks := bind.Check(rec, surrogate, document); checks[2].Status != receipt.Fail {
		t.Errorf("claim with a surrogate in it: %v", checks[2])
	}

	for _, bad := range []string{`{}`, `{"binding_key":"xx","claims":[]}`, `{"binding_key":"` + hex.EncodeToString(key) + `"}`, `{"binding_key":"` + hex.EncodeToString(key) + `","claims":[{"n":"1","claim_text":"x"}]}`, `[]`, `nope`} {
		if _, err := bind.ParseBundle([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func hmacEqual(a, b []byte) bool { return hmac.Equal(a, b) }

func bytes32(seed string) []byte {
	s := sha256.Sum256([]byte(seed))
	return s[:]
}

func ptr(s string) *string { return &s }

func str(s string) *canonical.Value { return &canonical.Value{Kind: canonical.String, Str: s} }
func num(n int64) *canonical.Value {
	return &canonical.Value{Kind: canonical.Number, Int: n, IsInt: true}
}

func set(obj *canonical.Value, key string, val *canonical.Value) {
	for i := range obj.Members {
		if obj.Members[i].Key == key {
			obj.Members[i].Value = val
			return
		}
	}
	obj.Members = append(obj.Members, canonical.Member{Key: key, Value: val})
}

func jsonString(s string) string {
	out, _ := canonical.Canonicalize(s)
	return string(out)
}

func fixtureKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "spec", "vectors", "test-key.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := canonical.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(v.Get("private_pkcs8_b64").Str)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.(ed25519.PrivateKey)
}
