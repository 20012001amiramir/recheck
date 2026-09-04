package chain_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/20012001amiramir/recheck/canonical"
	"github.com/20012001amiramir/recheck/chain"
	"github.com/20012001amiramir/recheck/merkle"
	"github.com/20012001amiramir/recheck/receipt"
)

func vector(t *testing.T, name string) *canonical.Value {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "spec", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	v, err := canonical.ParseLenient(data)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func fixtureKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	key := vector(t, "test-key.json")
	der, err := base64.StdEncoding.DecodeString(key.Get("private_pkcs8_b64").Str)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.(ed25519.PrivateKey)
}

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

// seal re-seals the vector receipt's body at a chain position, exactly as the issuer would: the
// body with the new id, seq, prev_hash and issued_at, self_hash over it, one issuer signature.
func seal(t *testing.T, body []byte, id string, seq int64, prevHash, issuedAt string, priv ed25519.PrivateKey) (string, string) {
	t.Helper()
	v, err := canonical.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	set(v, "id", str(id))
	set(v, "seq", num(seq))
	set(v, "prev_hash", str(prevHash))
	set(v, "issued_at", str(issuedAt))
	set(v, "signatures", &canonical.Value{Kind: canonical.Array})
	selfHash, err := canonical.SelfHash(v)
	if err != nil {
		t.Fatal(err)
	}
	set(v, "self_hash", str(selfHash))
	sig, err := receipt.Sign(priv, selfHash)
	if err != nil {
		t.Fatal(err)
	}
	entry := &canonical.Value{Kind: canonical.Object}
	set(entry, "key_id", str("eb-receipt-test"))
	set(entry, "alg", str("ed25519"))
	set(entry, "sig", str(sig))
	set(entry, "role", str("issuer"))
	set(v, "signatures", &canonical.Value{Kind: canonical.Array, Array: []*canonical.Value{entry}})
	out, err := canonical.Canonicalize(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(out), selfHash
}

// chainOf builds the three receipts of spec/vectors/root.json from receipt.json's body.
func chainOf(t *testing.T) (lines []string, hashes []string) {
	t.Helper()
	body, err := canonical.Canonicalize(vector(t, "receipt.json").Get("receipt"))
	if err != nil {
		t.Fatal(err)
	}
	priv := fixtureKey(t)
	prev := chain.Genesis
	for _, r := range vector(t, "root.json").Get("receipts").Array {
		line, selfHash := seal(t, body, r.Get("id").Str, r.Get("seq").Int, prev, r.Get("issued_at").Str, priv)
		lines = append(lines, line)
		hashes = append(hashes, selfHash)
		prev = selfHash
	}
	return lines, hashes
}

func TestGenesis(t *testing.T) {
	sum := sha256.Sum256([]byte("exhibitb.genesis.v1"))
	if hex.EncodeToString(sum[:]) != chain.Genesis {
		t.Errorf("genesis constant is %x", sum)
	}
}

func TestResealedReceiptsReproduceTheRootVector(t *testing.T) {
	// Spec §14: any receipt from receipt.json's body sealed at root.json's ids and times reproduces
	// its self_hash values exactly — and therefore its Merkle root.
	_, hashes := chainOf(t)
	rootVec := vector(t, "root.json")
	for i, r := range rootVec.Get("receipts").Array {
		if want := r.Get("self_hash").Str; hashes[i] != want {
			t.Errorf("receipt %d: self_hash %s, vector says %s", i+1, hashes[i], want)
		}
	}
	if got, _ := merkle.RootHex(hashes); got != rootVec.Get("root_file").Get("root").Str {
		t.Errorf("root %s, vector says %s", got, rootVec.Get("root_file").Get("root").Str)
	}
}

func TestReplay(t *testing.T) {
	lines, hashes := chainOf(t)
	keys, err := receipt.ParseKeySet([]byte(`[{"key_id":"eb-receipt-test","public_key":"+OIf8AWG2M/e4fqmltCC+xtj9kmks5fAk3UjznkHRuQ="}]`))
	if err != nil {
		t.Fatal(err)
	}
	src := strings.Join(lines, "\n") + "\n\n"

	for name, set := range map[string]*receipt.KeySet{"pinned": keys, "embedded only": nil} {
		rep := chain.Replay(strings.NewReader(src), set)
		if !rep.OK || rep.Checked != 3 || rep.HeadSeq != 3 || rep.HeadHash != hashes[2] || !rep.FromGenesis || rep.FirstBroken != nil {
			t.Errorf("%s: %+v", name, rep)
		}
	}

	// An empty file is an empty chain at genesis.
	rep := chain.Replay(strings.NewReader(""), keys)
	if !rep.OK || rep.Checked != 0 || rep.HeadSeq != 0 || rep.HeadHash != chain.Genesis {
		t.Errorf("empty: %+v", rep)
	}

	// A segment that does not start at genesis is checked internally.
	rep = chain.Replay(strings.NewReader(lines[1]+"\n"+lines[2]), keys)
	if !rep.OK || rep.Checked != 2 || rep.FirstSeq != 2 || rep.FromGenesis {
		t.Errorf("segment: %+v", rep)
	}

	sigAt := strings.Index(lines[2], `"sig":"`) + len(`"sig":"`)
	flippedSig := lines[2][:sigAt] + flip(lines[2][sigAt]) + lines[2][sigAt+1:]
	cases := []struct {
		name   string
		src    string
		seq    int64
		reason string
	}{
		{"edited body", strings.Join([]string{lines[0], strings.Replace(lines[1], `"overlap_bp":10000`, `"overlap_bp":9999`, 1), lines[2]}, "\n"), 2, "self_hash"},
		{"receipt removed", lines[0] + "\n" + lines[2], 3, "prev_hash"},
		{"receipts swapped", lines[1] + "\n" + lines[0], 1, "prev_hash"},
		// The link is checked before the hash, as the issuer's own replay does.
		{"wrong genesis", strings.Replace(lines[0], chain.Genesis, hashes[0], 1), 1, "prev_hash"},
		{"flipped signature", strings.Join([]string{lines[0], lines[1], flippedSig}, "\n"), 3, "signature"},
		{"not json", lines[0] + "\n{", 0, "self_hash"},
		{"unchained in the chain", lines[0] + "\n" + strings.Replace(strings.Replace(strings.Replace(lines[1], `"seq":2`, `"seq":null`, 1), `"prev_hash":"`+hashes[0]+`"`, `"prev_hash":null`, 1), `"kind":"exhibitb.receipt"`, `"kind":"exhibitb.receipt.unchained"`, 1), 0, "prev_hash"},
	}
	for _, c := range cases {
		rep := chain.Replay(strings.NewReader(c.src), keys)
		if rep.OK || rep.FirstBroken == nil || rep.FirstBroken.Seq != c.seq || rep.FirstBroken.Reason != c.reason {
			t.Errorf("%s: %+v", c.name, rep)
		}
	}

	// Under a pinned set the embedded key must be the pinned one; a re-signed receipt is caught
	// even though it is self-consistent.
	_, other, _ := ed25519.GenerateKey(nil)
	body, _ := canonical.Canonicalize(vector(t, "receipt.json").Get("receipt"))
	v, _ := canonical.Parse(body)
	set(v.Get("issuer"), "public_key", str(receipt.EncodeKey(other.Public().(ed25519.PublicKey))))
	resignedBody, _ := canonical.Canonicalize(v)
	resigned, _ := seal(t, resignedBody, "eb_2m4Kq8Xr7vTb3nHd", 1, chain.Genesis, "2026-09-03T10:00:00Z", other)
	rep = chain.Replay(strings.NewReader(resigned), nil)
	if !rep.OK {
		t.Errorf("re-signed receipt is self-consistent: %+v", rep)
	}
	rep = chain.Replay(strings.NewReader(resigned), keys)
	if rep.OK || rep.FirstBroken == nil || rep.FirstBroken.Reason != "signature" {
		t.Errorf("re-signed receipt under pinned keys: %+v", rep)
	}
}

// flip returns a different base64 character.
func flip(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}

func TestLink(t *testing.T) {
	lines, _ := chainOf(t)
	var recs []*receipt.Receipt
	for _, l := range lines {
		r, _, err := receipt.Parse([]byte(l))
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	if err := chain.Link(nil, recs[0]); err != nil {
		t.Error(err)
	}
	if err := chain.Link(recs[0], recs[1]); err != nil {
		t.Error(err)
	}
	if err := chain.Link(recs[1], recs[2]); err != nil {
		t.Error(err)
	}
	if chain.Link(nil, recs[1]) == nil || chain.Link(recs[0], recs[2]) == nil || chain.Link(recs[1], recs[0]) == nil {
		t.Error("broken links accepted")
	}
	un, _, err := receipt.Parse(func() []byte {
		out, _ := canonical.Canonicalize(vector(t, "receipt.json").Get("unchained").Get("receipt"))
		return out
	}())
	if err != nil {
		t.Fatal(err)
	}
	if chain.Link(nil, un) == nil || chain.Link(un, recs[1]) == nil {
		t.Error("an unchained receipt cannot be linked")
	}
}
