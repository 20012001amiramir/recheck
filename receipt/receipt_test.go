package receipt_test

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/20012001amiramir/recheck/canonical"
	"github.com/20012001amiramir/recheck/receipt"
)

func vector(t *testing.T, name string) *canonical.Value {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "spec", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	// Lenient: one tampered vector deliberately carries a lone surrogate, which the strict parser
	// (rightly) refuses. Pretty writes it back as the same \u escape.
	v, err := canonical.ParseLenient(data)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// pretty re-serialises a sub-value of a vector as a standalone document.
func pretty(t *testing.T, v *canonical.Value) []byte {
	t.Helper()
	out, err := canonical.Pretty(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func keySet(t *testing.T, key *canonical.Value) *receipt.KeySet {
	t.Helper()
	set, err := receipt.ParseKeySet(pretty(t, key))
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func statuses(res receipt.Result) map[string]string {
	out := map[string]string{}
	for _, c := range res.Checks {
		out[c.Name] = c.Status
	}
	return out
}

func expect(t *testing.T, name string, res receipt.Result, want map[string]string) {
	t.Helper()
	got := statuses(res)
	if len(res.Checks) != 5 {
		t.Errorf("%s: %d checks, want 5", name, len(res.Checks))
	}
	names := receipt.CheckNames
	if res.Receipt != nil && res.Receipt.Projected {
		names = receipt.ProjectionCheckNames
	}
	for i, n := range names {
		if i < len(res.Checks) && res.Checks[i].Name != n {
			t.Errorf("%s: check %d is %s, want %s", name, i, res.Checks[i].Name, n)
		}
	}
	for check, status := range want {
		if got[check] != status {
			t.Errorf("%s: %s = %s, want %s (%v)", name, check, got[check], status, res.Checks)
		}
	}
}

// edit applies textual edits to the pretty-printed valid receipt. Each edit is {from, to} or
// {from, to, "2"} to replace the second occurrence instead of the first.
func edit(t *testing.T, vec *canonical.Value, edits ...[]string) []byte {
	t.Helper()
	src := string(pretty(t, vec.Get("receipt")))
	for _, e := range edits {
		from, to := e[0], e[1]
		at := strings.Index(src, from)
		if len(e) > 2 && e[2] == "2" && at >= 0 {
			next := strings.Index(src[at+len(from):], from)
			if next < 0 {
				at = -1
			} else {
				at += len(from) + next
			}
		}
		if at < 0 {
			t.Fatalf("edit: %q not found", from)
		}
		src = src[:at] + to + src[at+len(from):]
	}
	return []byte(src)
}

// withMember replaces one top-level member of the valid receipt.
func withMember(t *testing.T, vec *canonical.Value, key string, val *canonical.Value) []byte {
	t.Helper()
	src := vec.Get("receipt")
	out := &canonical.Value{Kind: canonical.Object}
	for _, m := range src.Members {
		if m.Key == key {
			m.Value = val
		}
		out.Members = append(out.Members, m)
	}
	return pretty(t, out)
}

// sigOf is the issuer signature of the vector receipt.
func sigOf(t *testing.T, vec *canonical.Value) string {
	t.Helper()
	return vec.Get("receipt").Get("signatures").Array[0].Get("sig").Str
}

// fixtureSig is that signature as a JSON member, for building extra signature entries.
func fixtureSig(t *testing.T, vec *canonical.Value) string {
	t.Helper()
	return `"sig":"` + sigOf(t, vec) + `"`
}

const b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// flipBit changes the base64 symbol at index i so that it still matches the shape regex.
func flipBit(s string, i int) string {
	c := strings.IndexByte(b64Alphabet, s[i])
	return s[:i] + string(b64Alphabet[c^1]) + s[i+1:]
}

// nonCanonical sets an unused trailing bit of the last data symbol: the same shape, a spelling
// that does not re-encode to itself.
func nonCanonical(s string) string { return flipBit(s, strings.IndexByte(s, '=')-1) }

// urlSafe rewrites one symbol into the URL-safe alphabet.
func urlSafe(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i] + "_" + s[i+1:]
	}
	return strings.Replace(s, "+", "-", 1)
}

func TestValidReceipt(t *testing.T) {
	vec := vector(t, "receipt.json")
	keys := keySet(t, vec.Get("key"))
	src := pretty(t, vec.Get("receipt"))

	res := receipt.Verify(src, keys)
	expect(t, "receipt", res, map[string]string{"schema": "pass", "self_hash": "pass", "signature": "pass", "key_pinned": "pass", "chain_fields": "pass"})
	if !res.OK() || receipt.ExitCode(res.Checks) != 0 {
		t.Errorf("valid receipt: ok=%v exit=%d", res.OK(), receipt.ExitCode(res.Checks))
	}
	if res.Receipt == nil || res.Receipt.ID != "eb_2m4Kq8Xr7vTb3nHd" || res.Receipt.Seq == nil || *res.Receipt.Seq != 1 || len(res.Receipt.Claims) != 3 {
		t.Fatalf("parsed receipt: %+v", res.Receipt)
	}
	if res.Receipt.Claims[1].Exists.Registry == nil || res.Receipt.Claims[1].Exists.Registry.Agency != "crossref" {
		t.Errorf("claim 2 registry: %+v", res.Receipt.Claims[1].Exists.Registry)
	}
	if res.Receipt.Claims[0].Exists.FinalURL == nil || *res.Receipt.Claims[0].Exists.FinalURL != "https://cdn.example.org/reports/2026/q1.pdf" {
		t.Errorf("claim 1 final_url: %v", res.Receipt.Claims[0].Exists.FinalURL)
	}

	selfHash, err := canonical.SelfHash(vec.Get("receipt"))
	if err != nil || selfHash != vec.Get("self_hash").Str {
		t.Errorf("self_hash %s (%v), want %s", selfHash, err, vec.Get("self_hash").Str)
	}
	full, err := canonical.Canonicalize(vec.Get("receipt"))
	if err != nil || canonical.Sha256Hex(full) != vec.Get("canonical_sha256").Str {
		t.Errorf("canonical_sha256 %s (%v), want %s", canonical.Sha256Hex(full), err, vec.Get("canonical_sha256").Str)
	}

	// Whitespace and member order are irrelevant: the canonical bytes verify the same.
	res = receipt.Verify(full, keys)
	if !res.OK() {
		t.Errorf("canonical bytes: %v", res.Checks)
	}
}

func TestProjection(t *testing.T) {
	vec := vector(t, "receipt.json")
	keys := keySet(t, vec.Get("key"))
	res := receipt.Verify(pretty(t, vec.Get("projection")), keys)
	// A projection is signed in its own right, so it passes outright (exit 0), with checks 2 and 3
	// its own hash and signature rather than the receipt's.
	expect(t, "projection", res, map[string]string{"schema": "pass", "projection_self_hash": "pass", "projection_signature": "pass", "key_pinned": "pass", "chain_fields": "pass"})
	if !res.OK() || receipt.ExitCode(res.Checks) != 0 || res.Receipt == nil || !res.Receipt.Projected {
		t.Fatalf("projection: ok=%v exit=%d receipt=%v", res.OK(), receipt.ExitCode(res.Checks), res.Receipt)
	}
	if d := res.Receipt.Claims[0].Locator.Domain; d == nil || *d != "example.org" {
		t.Errorf("projected domain: %v", d)
	}

	// Our own projection of the receipt is the vector's projection minus its projection_sig: show
	// cannot sign, so the derived view carries every other member but not the signature.
	r, raw, err := receipt.Parse(pretty(t, vec.Get("receipt")))
	if err != nil {
		t.Fatal(err)
	}
	proj, err := receipt.Project(r, raw)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := canonical.Canonicalize(proj)
	withoutSig := &canonical.Value{Kind: canonical.Object}
	for _, m := range vec.Get("projection").Members {
		if m.Key == "projection_sig" {
			continue
		}
		withoutSig.Members = append(withoutSig.Members, m)
	}
	want, _ := canonical.Canonicalize(withoutSig)
	if string(got) != string(want) {
		t.Errorf("projection differs:\n got %s\nwant %s", got, want)
	}
	// A projection projects to itself, projection_sig kept.
	again, _ := receipt.Project(res.Receipt, res.Raw)
	got2, _ := canonical.Canonicalize(again)
	wantSigned, _ := canonical.Canonicalize(vec.Get("projection"))
	if string(got2) != string(wantSigned) {
		t.Error("projection of a projection changed")
	}

	// The vector's rewritten projection — a count and a verdict changed, signatures left intact —
	// fails projection_signature, the check that binds the visible fields.
	tv := vec.Get("projection_tampered")
	res = receipt.Verify(pretty(t, tv.Get("receipt")), keys)
	if res.OK() {
		t.Error("tampered projection verified")
	}
	if ff := receipt.FirstFailure(res.Checks); ff == nil || ff.Name != tv.Get("first_failure").Str {
		t.Errorf("tampered projection first_failure %v, want %s", ff, tv.Get("first_failure").Str)
	}
}

func TestLegacyVector(t *testing.T) {
	vec := vector(t, "receipt.json")
	keys := keySet(t, vec.Get("key"))
	leg := vec.Get("legacy")
	if leg == nil {
		t.Fatal("receipt.json carries no legacy vector")
	}
	// A body sealed at engine 0.1.0, before the format was finalized: no claims[].source_of, no
	// counts.not_checked, no registry.method. It is immutable and must pass outright (§15).
	res := receipt.Verify(pretty(t, leg.Get("receipt")), keys)
	expect(t, "legacy receipt", res, map[string]string{"schema": "pass", "self_hash": "pass", "signature": "pass", "key_pinned": "pass", "chain_fields": "pass"})
	if receipt.ExitCode(res.Checks) != 0 || res.Receipt == nil {
		t.Fatalf("legacy receipt: exit %d %v", receipt.ExitCode(res.Checks), res.Checks)
	}
	if res.Receipt.Engine.Version != leg.Get("engine_version").Str || res.Receipt.SelfHash != leg.Get("self_hash").Str {
		t.Errorf("legacy receipt: version %s, self_hash %s", res.Receipt.Engine.Version, res.Receipt.SelfHash)
	}
	// Read as the defaults, never written into the body: the hash above is over the bytes as they are.
	if res.Receipt.Claims[0].SourceOf != "body" || res.Receipt.Counts.NotChecked != 0 {
		t.Errorf("legacy defaults: source_of %q, not_checked %d", res.Receipt.Claims[0].SourceOf, res.Receipt.Counts.NotChecked)
	}
	if m := res.Receipt.Claims[1].Exists.Registry.Method; m == nil || *m != "lookup" {
		t.Errorf("legacy registry.method: %v", m)
	}
	// Its projection carries exactly what the body carries, and passes as a projection.
	res = receipt.Verify(pretty(t, leg.Get("projection")), keys)
	expect(t, "legacy projection", res, map[string]string{"schema": "pass", "projection_self_hash": "pass", "projection_signature": "pass", "key_pinned": "pass", "chain_fields": "pass"})
	if receipt.ExitCode(res.Checks) != 0 {
		t.Errorf("legacy projection: exit %d %v", receipt.ExitCode(res.Checks), res.Checks)
	}

	// Nothing else is relaxed: a member that is present must still match its shape, and an
	// unknown member is still refused.
	src := string(pretty(t, leg.Get("receipt")))
	for name, edited := range map[string]string{
		"source_of present but not an enum": strings.Replace(src, `"level": "SAYS"`, `"source_of": "prose", "level": "SAYS"`, 1),
		"not_checked present but negative":  strings.Replace(src, `"claims": 3,`, `"claims": 3, "not_checked": -1,`, 1),
		"unknown member":                    strings.Replace(src, `"v": 1,`, `"v": 1, "extra": true,`, 1),
	} {
		if ff := receipt.FirstFailure(receipt.Verify([]byte(edited), keys).Checks); ff == nil || ff.Name != "schema" {
			t.Errorf("%s: %v", name, ff)
		}
	}

	// The same omissions in a body at 0.2.0 are a schema failure, at the first claim's source_of.
	tv := vec.Get("tampered").Array[5]
	res = receipt.Verify(pretty(t, tv.Get("receipt")), keys)
	if ff := receipt.FirstFailure(res.Checks); ff == nil || ff.Name != "schema" || !strings.HasPrefix(ff.Detail, "$.claims[0].source_of:") {
		t.Errorf("finalized format without its members: %v", ff)
	}
	// So is any version that is not below 0.2.0, however it is spelled.
	for _, v := range []string{"0.2.0", "0.2.0-rc.1", "0.10.0", "1.0.0"} {
		edited := strings.Replace(src, `"version": "0.1.0"`, `"version": "`+v+`"`, 1)
		if ff := receipt.FirstFailure(receipt.Verify([]byte(edited), keys).Checks); ff == nil || ff.Name != "schema" {
			t.Errorf("version %s must require the members: %v", v, ff)
		}
	}
}

func TestUnchained(t *testing.T) {
	vec := vector(t, "receipt.json")
	keys := keySet(t, vec.Get("key"))
	un := vec.Get("unchained")
	res := receipt.Verify(pretty(t, un.Get("receipt")), keys)
	expect(t, "unchained", res, map[string]string{"schema": "pass", "self_hash": "pass", "signature": "pass", "key_pinned": "pass", "chain_fields": "skip"})
	if receipt.ExitCode(res.Checks) != 0 {
		t.Errorf("unchained exit %d", receipt.ExitCode(res.Checks))
	}
	if res.Receipt.SelfHash != un.Get("self_hash").Str {
		t.Errorf("unchained self_hash %s want %s", res.Receipt.SelfHash, un.Get("self_hash").Str)
	}
	if !strings.Contains(res.Checks[4].Detail, "not anchored to the public chain") {
		t.Errorf("chain_fields detail: %s", res.Checks[4].Detail)
	}
	// An unchained receipt carrying a chain position fails chain_fields.
	src := strings.Replace(string(pretty(t, un.Get("receipt"))), `"seq": null`, `"seq": 1`, 1)
	res = receipt.Verify([]byte(src), keys)
	expect(t, "unchained with seq", res, map[string]string{"schema": "pass", "self_hash": "fail", "chain_fields": "fail"})
}

func TestTamperedVectors(t *testing.T) {
	vec := vector(t, "receipt.json")
	keys := keySet(t, vec.Get("key"))
	tampered := vec.Get("tampered").Array
	if len(tampered) < 3 {
		t.Fatalf("%d tampered vectors", len(tampered))
	}
	for _, tv := range tampered {
		name := tv.Get("name").Str
		want := tv.Get("first_failure").Str
		res := receipt.Verify(pretty(t, tv.Get("receipt")), keys)
		if res.OK() {
			t.Errorf("%s: ok", name)
		}
		ff := receipt.FirstFailure(res.Checks)
		if ff == nil || ff.Name != want {
			t.Errorf("%s: first_failure %v, want %s", name, ff, want)
		}
		if receipt.ExitCode(res.Checks) != 1 {
			t.Errorf("%s: exit %d", name, receipt.ExitCode(res.Checks))
		}
		if want == "schema" {
			for _, c := range res.Checks[1:] {
				if c.Status != receipt.Skip {
					t.Errorf("%s: %s is %s after a schema failure", name, c.Name, c.Status)
				}
			}
		}
	}
}

func TestKeyPinning(t *testing.T) {
	vec := vector(t, "receipt.json")
	src := pretty(t, vec.Get("receipt"))

	res := receipt.Verify(src, nil)
	expect(t, "no keys", res, map[string]string{"signature": "pass", "key_pinned": "skip"})
	res = receipt.Verify(src, receipt.NewKeySet())
	expect(t, "empty keys", res, map[string]string{"key_pinned": "skip"})
	if receipt.ExitCode(res.Checks) != 0 {
		t.Errorf("empty key set must not change the exit code: %d", receipt.ExitCode(res.Checks))
	}

	other, err := receipt.ParseKeySet([]byte(`{"keys":[{"key_id":"eb-receipt-2026-09","alg":"ed25519","purpose":"receipt","public_key":"+OIf8AWG2M/e4fqmltCC+xtj9kmks5fAk3UjznkHRuQ=","created_at":"2026-09-01T00:00:00Z","retired_at":null}]}`))
	if err != nil {
		t.Fatal(err)
	}
	res = receipt.Verify(src, other)
	expect(t, "unknown id", res, map[string]string{"key_pinned": "warn"})
	if receipt.ExitCode(res.Checks) != 2 || !strings.Contains(res.Checks[3].Detail, "issuer key not pinned — verified against the key inside the receipt only") {
		t.Errorf("unknown id: exit %d detail %q", receipt.ExitCode(res.Checks), res.Checks[3].Detail)
	}

	// The issuer's id pinned to someone else's key: the receipt is re-signed by an impostor.
	pub, _, _ := ed25519.GenerateKey(nil)
	wrong, err := receipt.ParseKeySet([]byte(`[{"key_id":"eb-receipt-test","public_key":"` + base64.StdEncoding.EncodeToString(pub) + `"}]`))
	if err != nil {
		t.Fatal(err)
	}
	res = receipt.Verify(src, wrong)
	expect(t, "different key", res, map[string]string{"signature": "pass", "key_pinned": "fail"})

	// A root key under the receipt's id is not a receipt key.
	rootOnly, _ := receipt.ParseKeySet([]byte(`[{"key_id":"eb-receipt-test","purpose":"root","public_key":"+OIf8AWG2M/e4fqmltCC+xtj9kmks5fAk3UjznkHRuQ="}]`))
	res = receipt.Verify(src, rootOnly)
	expect(t, "wrong purpose", res, map[string]string{"key_pinned": "warn"})

	// A pinned entry that is not canonical base64 is a broken pin: check 4 fails on it (§13).
	for _, brokenPin := range []string{
		`[{"key_id":"eb-receipt-test","public_key":"+OIf8AWG2M/e4fqmltCC+xtj9kmks5fAk3UjznkHRuR="}]`, // non-zero trailing bits
		`[{"key_id":"eb-receipt-test","public_key":"+OIf8AWG2M_e4fqmltCC-xtj9kmks5fAk3UjznkHRuQ="}]`, // url-safe alphabet
		`[{"key_id":"eb-receipt-test","public_key":"short"}]`,
	} {
		broken, err := receipt.ParseKeySet([]byte(brokenPin))
		if err != nil {
			t.Fatalf("broken pin must load: %v", err)
		}
		res = receipt.Verify(src, broken)
		expect(t, "broken pin", res, map[string]string{"signature": "pass", "key_pinned": "fail"})
	}

	// Malformed key sets are refused up front.
	for _, bad := range []string{
		`{"keys":[{"key_id":"receipt-test","public_key":"+OIf8AWG2M/e4fqmltCC+xtj9kmks5fAk3UjznkHRuQ="}]}`,
		`{"keys":[{"key_id":"eb-receipt-test","public_key":"+OIf8AWG2M/e4fqmltCC+xtj9kmks5fAk3UjznkHRuQ="},{"key_id":"eb-receipt-test","public_key":"` + base64.StdEncoding.EncodeToString(pub) + `"}]}`,
		`{"keys":[{"key_id":"eb-receipt-test","public_key":42}]}`,
		`{"keys":{}}`,
		`[1]`,
		`nope`,
	} {
		if _, err := receipt.ParseKeySet([]byte(bad)); err == nil {
			t.Errorf("accepted bad key set %s", bad)
		}
	}
	pinned, err := receipt.Pinned()
	if err != nil {
		t.Fatalf("compiled-in keys: %v", err)
	}
	if _, ok := pinned.Lookup("receipt", "eb-receipt-test"); ok {
		t.Error("the fixture key must never be pinned")
	}
	if _, ok := pinned.Lookup("root", "eb-root-test"); ok {
		t.Error("the fixture root key must never be pinned")
	}
}

func TestSignatureReproducesVector(t *testing.T) {
	vec := vector(t, "receipt.json")
	key := vector(t, "test-key.json")
	der, err := base64.StdEncoding.DecodeString(key.Get("private_pkcs8_b64").Str)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	priv := parsed.(ed25519.PrivateKey)
	if receipt.EncodeKey(priv.Public().(ed25519.PublicKey)) != key.Get("public_key").Str {
		t.Error("fixture public key does not match its private half")
	}
	sig, err := receipt.Sign(priv, vec.Get("self_hash").Str)
	if err != nil {
		t.Fatal(err)
	}
	if want := vec.Get("receipt").Get("signatures").Array[0].Get("sig").Str; sig != want {
		t.Errorf("signature %s, want %s", sig, want)
	}
	if !receipt.VerifySignature(key.Get("public_key").Str, vec.Get("self_hash").Str, sig) {
		t.Error("own signature does not verify")
	}
	if receipt.VerifySignature(key.Get("public_key").Str, vec.Get("self_hash").Str, "x"+sig[1:]) {
		t.Error("altered signature verifies")
	}
	if receipt.VerifySignature(key.Get("public_key").Str[:43]+"A", vec.Get("self_hash").Str, sig) {
		t.Error("malformed key accepted")
	}
	if _, err := receipt.DecodeKey(key.Get("public_key").Str[:42] + "R="); err == nil {
		t.Error("non-canonical base64 (trailing bits set) accepted")
	}
}

func TestSchemaStrictness(t *testing.T) {
	vec := vector(t, "receipt.json")
	keys := keySet(t, vec.Get("key"))
	sig := sigOf(t, vec)
	cases := []struct {
		name, from, to, path string
	}{
		{"unknown top-level member", `"v": 1,`, `"v": 1, "extra": true,`, "$.extra"},
		{"unknown member in a claim", `"refutation_attempted": true,`, `"refutation_attempted": true, "note": "x",`, "$.claims[0].note"},
		{"missing member", `"holds_attempted": 1`, `"holds_attempted_": 1`, "$.counts.holds_attempted"},
		{"non-integer number", `"overlap_bp": 10000`, `"overlap_bp": 10000.5`, "$.claims[0].says.overlap_bp"},
		{"bp above 10000", `"overlap_bp": 10000`, `"overlap_bp": 10001`, "$.claims[0].says.overlap_bp"},
		{"span start after end", `120,`, `300,`, "$.claims[0].doc_span"},
		{"span with three entries", `120,`, `120, 121,`, "$.claims[0].doc_span"},
		{"wrong literal", `"name": "EXHIBIT B"`, `"name": "EXHIBIT C"`, "$.issuer.name"},
		{"disclaimer edited", `Not a claim of truth.`, `Not a claim of anything.`, "$.scope_disclaimer"},
		{"uppercase hex", `"key_sha256": "e812574a`, `"key_sha256": "E812574A`, "$.binding.key_sha256"},
		{"url with a space", `"value": "https://www.example.org/reports/2026/q1.pdf"`, `"value": "https://www.example.org/reports/2026/q 1.pdf"`, "$.claims[0].locator.value"},
		{"url with U+00A0", `"value": "https://www.example.org/reports/2026/q1.pdf"`, "\"value\": \"https://www.example.org/reports/2026/q 1.pdf\"", "$.claims[0].locator.value"},
		{"url with U+3000", `"value": "https://www.example.org/reports/2026/q1.pdf"`, "\"value\": \"https://www.example.org/reports/2026/q　1.pdf\"", "$.claims[0].locator.value"},
		{"url with a quote", `"final_url": "https://cdn.example.org/reports/2026/q1.pdf"`, `"final_url": "https://cdn.example.org/reports/2026/q1.pdf'"`, "$.claims[0].exists.final_url"},
		{"url with a pipe", `"final_url": "https://cdn.example.org/reports/2026/q1.pdf"`, `"final_url": "https://cdn.example.org/reports/2026/q1.pdf|x"`, "$.claims[0].exists.final_url"},
		{"ftp url", `"url": "https://exhibitb.autofract.com"`, `"url": "ftp://exhibitb.autofract.com"`, "$.issuer.url"},
		{"lone surrogate", `"extractor": "unpdf@1"`, `"extractor": "\ud800"`, "$.document.extractor"},
		{"timestamp with millis", `"issued_at": "2026-09-03T11:22:44Z"`, `"issued_at": "2026-09-03T11:22:44.000Z"`, "$.issued_at"},
		{"dissent not null", `"dissent": null`, `"dissent": {}`, "$.claims[0].dissent"},
		{"unsupported locator with a url", `"url": null`, `"url": "https://x.example"`, "$.claims[2].locator.url"},
		{"bad receipt id", `"id": "eb_2m4Kq8Xr7vTb3nHd"`, `"id": "eb_2m4Kq8Xr7vTb3nH0"`, "$.id"},
		{"bad key id", `"key_id": "eb-receipt-test"`, `"key_id": "eb-Receipt-test"`, "$.issuer.key_id"},
		{"seq zero", `"seq": 1,`, `"seq": 0,`, "$.seq"},
		{"seq as string", `"seq": 1,`, `"seq": "1",`, "$.seq"},
		{"retriever status out of range", `"status": 403,`, `"status": 600,`, "$.claims[1].exists.retrievers[0].status"},
		{"too many signatures", `"signatures": [`, `"signatures": [` + strings.Repeat(`{"key_id":"eb-receipt-test","alg":"ed25519",`+fixtureSig(t, vec)+`,"role":"counter"},`, 8), "$.signatures"},
		{"model id too short", `"model": "extract-model-2026-06"`, `"model": "x"`, "$.models[0].model"},
		{"reason is a sentence", `"reason": "no_source_text"`, `"reason": "no source text"`, "$.claims[1].says.reason"},
		{"case citation that is prose", `"value": "10.1136/bmj.n1234"`, `"value": "410 Some Reporter 113"`, "$.claims[1].locator.value"},
		{"registry name_check outside its enum", `"method": null`, `"method": null, "name_check": "maybe"`, "$.claims[1].exists.registry.name_check"},
		{"registry reason is a sentence", `"method": null`, `"method": null, "reason": "another case"`, "$.claims[1].exists.registry.reason"},
		{"registry cluster_id negative", `"method": null`, `"method": null, "cluster_id": -1`, "$.claims[1].exists.registry.cluster_id"},
		{"registry cluster_id as string", `"method": null`, `"method": null, "cluster_id": "2049"`, "$.claims[1].exists.registry.cluster_id"},
		{"non-canonical public key (trailing bits)", `"public_key": "+OIf8AWG2M/e4fqmltCC+xtj9kmks5fAk3UjznkHRuQ="`, `"public_key": "+OIf8AWG2M/e4fqmltCC+xtj9kmks5fAk3UjznkHRuR="`, "$.issuer.public_key"},
		{"non-canonical signature (trailing bits)", sig, nonCanonical(sig), "$.signatures[0].sig"},
		{"url-safe signature alphabet", sig, urlSafe(sig), "$.signatures[0].sig"},
		{"counts not_found missing", `"not_found": 0,`, ``, "$.counts.not_found"},
	}
	for _, c := range cases {
		res := receipt.Verify(edit(t, vec, []string{c.from, c.to}), keys)
		ff := receipt.FirstFailure(res.Checks)
		if ff == nil || ff.Name != "schema" {
			t.Errorf("%s: first failure %v, want schema", c.name, ff)
			continue
		}
		if !strings.HasPrefix(ff.Detail, c.path+":") && !strings.HasPrefix(ff.Detail, c.path+"[") {
			t.Errorf("%s: detail %q does not name %s", c.name, ff.Detail, c.path)
		}
	}

	// Whole-document shapes.
	for name, src := range map[string]string{
		"top-level array":  `[]`,
		"top-level string": `"eb_2m4Kq8Xr7vTb3nHd"`,
		"bom":              "\xef\xbb\xbf" + string(pretty(t, vec.Get("receipt"))),
		"duplicate key":    strings.Replace(string(pretty(t, vec.Get("receipt"))), `"v": 1,`, `"v": 1, "v": 1,`, 1),
		"not json":         `{`,
		"empty":            ``,
	} {
		res := receipt.Verify([]byte(src), keys)
		if ff := receipt.FirstFailure(res.Checks); ff == nil || ff.Name != "schema" {
			t.Errorf("%s: %v", name, res.Checks)
		}
		if len(res.Checks) != 5 || receipt.ExitCode(res.Checks) != 1 {
			t.Errorf("%s: %d checks, exit %d", name, len(res.Checks), receipt.ExitCode(res.Checks))
		}
	}

	// Things the schema must accept.
	accept := []struct {
		name  string
		edits [][]string
	}{
		{"a counter signature", [][]string{{`"role": "issuer"`, `"role": "issuer"}, {"key_id":"eb-receipt-counter-abc","alg":"ed25519",` + fixtureSig(t, vec) + `,"role":"counter"`}}},
		{"case citation", [][]string{{`"type": "doi"`, `"type": "case"`}, {`"value": "10.1136/bmj.n1234"`, `"value": "410 U.S. 113"`}}},
		{"case citation, three reporter tokens", [][]string{{`"type": "doi"`, `"type": "case"`}, {`"value": "10.1136/bmj.n1234"`, `"value": "123 F. Supp. 2d 456"`}}},
		{"case citation, the Illinois public-domain form", [][]string{{`"type": "doi"`, `"type": "case"`}, {`"value": "10.1136/bmj.n1234"`, `"value": "2025 IL App (4th) 241427"`}}},
		{"the case registry's members, present", [][]string{{`"method": null`, `"method": "name_search", "reason": "citation_not_indexed", "name_check": "match", "cluster_id": 10868210`}}},
		{"the case registry's members, null", [][]string{{`"method": null`, `"method": "search", "reason": null, "name_check": null, "cluster_id": null`}}},
		{"the case registry's members, some absent", [][]string{{`"method": null`, `"method": "search", "name_check": "mismatch"`}}},
		{"the case registry's name_check uncertain", [][]string{{`"method": null`, `"method": "search", "name_check": "uncertain", "cluster_id": 7`}}},
		{"neutral citation", [][]string{{`"type": "doi"`, `"type": "case"`}, {`"value": "10.1136/bmj.n1234"`, `"value": "[2019] EWHC 12"`}}},
		{"law report citation, a volume after the year", [][]string{{`"type": "doi"`, `"type": "case"`}, {`"value": "10.1136/bmj.n1234"`, `"value": "[2010] 1 AC 123"`}}},
		{"law report citation, two reporter tokens", [][]string{{`"type": "doi"`, `"type": "case"`}, {`"value": "10.1136/bmj.n1234"`, `"value": "[2020] 1 All ER 123"`}}},
		{"pmid", [][]string{{`"type": "doi"`, `"type": "pmid"`}, {`"value": "10.1136/bmj.n1234"`, `"value": "31234567"`}}},
		{"retriever unavailable", [][]string{{`"status": 403,`, `"status": "unavailable",`}}},
		{"number spelled with an exponent", [][]string{{`"bytes": 812004,`, `"bytes": 8.12004e5,`}}},
		{"unicode in a url", [][]string{{`"value": "https://www.example.org/reports/2026/q1.pdf"`, `"value": "https://www.example.org/reports/2026/q1-é.pdf"`}}},
	}
	for _, c := range accept {
		res := receipt.Verify(edit(t, vec, c.edits...), keys)
		if res.Checks[0].Status != receipt.Pass {
			t.Errorf("%s: %s", c.name, res.Checks[0].Detail)
		}
	}
	// Re-spelling a number does not move the hash.
	res := receipt.Verify(edit(t, vec, []string{`"bytes": 812004,`, `"bytes": 8.12004e5,`}), keys)
	if !res.OK() {
		t.Errorf("exponent spelling: %v", res.Checks)
	}
}

func TestSignatureRules(t *testing.T) {
	vec := vector(t, "receipt.json")
	keys := keySet(t, vec.Get("key"))
	sig := sigOf(t, vec)
	cases := []struct {
		name string
		src  []byte
		want string
	}{
		{"two issuer signatures", edit(t, vec, []string{`"role": "issuer"`, `"role": "issuer"}, {"key_id":"eb-receipt-test","alg":"ed25519",` + fixtureSig(t, vec) + `,"role":"issuer"`}), "2 issuer signatures"},
		{"only a counter signature", edit(t, vec, []string{`"role": "issuer"`, `"role": "counter"`}), "no issuer signature"},
		{"empty signatures", withMember(t, vec, "signatures", &canonical.Value{Kind: canonical.Array}), "no issuer signature"},
		{"key id mismatch", edit(t, vec, []string{`"key_id": "eb-receipt-test"`, `"key_id": "eb-receipt-other"`, "2"}), "is not the issuer's"},
		{"flipped signature byte", edit(t, vec, []string{sig, flipBit(sig, 0)}), "does not verify"},
	}
	for _, c := range cases {
		res := receipt.Verify(c.src, keys)
		ff := receipt.FirstFailure(res.Checks)
		if ff == nil || ff.Name != "signature" || !strings.Contains(ff.Detail, c.want) {
			t.Errorf("%s: %v", c.name, res.Checks)
			continue
		}
		if res.Checks[1].Status != receipt.Pass {
			t.Errorf("%s: self_hash must still pass, got %v", c.name, res.Checks[1])
		}
	}
}

func TestRegistrableHost(t *testing.T) {
	cases := map[string]string{
		"https://www.example.org/reports/q1.pdf":      "example.org",
		"https://pubmed.ncbi.nlm.nih.gov/31234567/":   "nih.gov",
		"https://www.bmj.co.uk/content/1":             "bmj.co.uk",
		"https://Example.COM:8443/x":                  "example.com",
		"http://127.0.0.1:8080/x":                     "127.0.0.1",
		"http://[::1]/x":                              "",
		"http://localhost/x":                          "localhost",
		"https://a.b.c.d.example.com.au/":             "example.com.au",
		"https://www./":                               "",
		"not a url":                                   "",
		"https://user:pw@sub.example.net/p?q=1#f":     "example.net",
		"https://cdn.example.org/reports/2026/q1.pdf": "example.org",
	}
	for in, want := range cases {
		if got := receipt.RegistrableHost(in); got != want {
			t.Errorf("%s: %q want %q", in, got, want)
		}
	}
}
