package root_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/20012001amiramir/recheck/canonical"
	"github.com/20012001amiramir/recheck/merkle"
	"github.com/20012001amiramir/recheck/receipt"
	"github.com/20012001amiramir/recheck/root"
)

const genesis = "3058620acf7ca95f8cc2c8970e7fc04afdbdeab9e688603bdd2e03a3bfcb588f"

func vector(t *testing.T) *canonical.Value {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "spec", "vectors", "root.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := canonical.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func pretty(t *testing.T, v *canonical.Value) []byte {
	t.Helper()
	out, err := canonical.Pretty(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func keys(t *testing.T, vec *canonical.Value) *receipt.KeySet {
	t.Helper()
	set, err := receipt.ParseKeySet(pretty(t, vec.Get("key")))
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func status(checks []receipt.Check, name string) string {
	for _, c := range checks {
		if c.Name == name {
			return c.Status
		}
	}
	return "missing"
}

func TestVector(t *testing.T) {
	vec := vector(t)
	rf := vec.Get("root_file")

	// The three receipts chain from genesis.
	prev := genesis
	var leaves []string
	for i, r := range vec.Get("receipts").Array {
		if r.Get("prev_hash").Str != prev {
			t.Errorf("receipt %d prev_hash %s, want %s", i, r.Get("prev_hash").Str, prev)
		}
		if r.Get("seq").Int != int64(i+1) {
			t.Errorf("receipt %d seq %d", i, r.Get("seq").Int)
		}
		prev = r.Get("self_hash").Str
		leaves = append(leaves, prev)
	}

	got, err := canonical.Canonicalize(rf)
	if err != nil || string(got) != vec.Get("root_file_canonical").Str {
		t.Errorf("canonical root file:\n got %s\nwant %s (%v)", got, vec.Get("root_file_canonical").Str, err)
	}
	sh, err := canonical.SelfHash(rf)
	if err != nil || sh != rf.Get("self_hash").Str {
		t.Errorf("self_hash %s (%v) want %s", sh, err, rf.Get("self_hash").Str)
	}
	if r, ok := merkle.RootHex(leaves); !ok || r != rf.Get("root").Str {
		t.Errorf("MTH over the three receipts %s, root file says %s", r, rf.Get("root").Str)
	}
	if rf.Get("prev_root").Str != genesis {
		t.Errorf("prev_root %s", rf.Get("prev_root").Str)
	}
	if rf.Get("head_hash").Str != leaves[2] {
		t.Errorf("head_hash %s", rf.Get("head_hash").Str)
	}

	file, checks := root.Verify(pretty(t, rf), keys(t, vec))
	for _, name := range []string{"root_schema", "root_self_hash", "root_signature"} {
		if status(checks, name) != receipt.Pass {
			t.Errorf("%s: %v", name, checks)
		}
	}
	if file == nil || file.Count != 3 || file.Date != "2026-09-03" || *file.FirstSeq != 1 || *file.LastSeq != 3 {
		t.Fatalf("parsed file: %+v", file)
	}

	for i, p := range vec.Get("proofs").Array {
		id := p.Get("receipt_id").Str
		selfHash := p.Get("self_hash").Str
		c := root.Inclusion(pretty(t, p), file, id, selfHash)
		if c.Status != receipt.Pass {
			t.Errorf("proof %d: %v", i, c)
		}
		if c := root.Inclusion(pretty(t, p), file, id, leaves[(i+1)%3]); c.Status != receipt.Fail || !strings.Contains(c.Detail, "proof is for self_hash") {
			t.Errorf("proof %d for another receipt: %v", i, c)
		}
		if c := root.Inclusion(pretty(t, p), file, "eb_9wXk3rPn6TzQ2mHf", selfHash); c.Status != receipt.Fail {
			t.Errorf("proof %d for another id: %v", i, c)
		}
		// A wrong index rebuilds a different root.
		wrong := strings.Replace(string(pretty(t, p)), `"leaf_index": `+string(rune('0'+i)), `"leaf_index": `+string(rune('0'+(i+1)%3)), 1)
		if c := root.Inclusion([]byte(wrong), file, id, selfHash); c.Status != receipt.Fail {
			t.Errorf("proof %d at the wrong index: %v", i, c)
		}
		// The proof must point at this root file.
		other := *file
		other.Count = 4
		if c := root.Inclusion(pretty(t, p), &other, id, selfHash); c.Status != receipt.Fail || !strings.Contains(c.Detail, "count") {
			t.Errorf("proof %d against a different count: %v", i, c)
		}
		other = *file
		other.Root = genesis
		if c := root.Inclusion(pretty(t, p), &other, id, selfHash); c.Status != receipt.Fail || !strings.Contains(c.Detail, "root file's") {
			t.Errorf("proof %d against a different root: %v", i, c)
		}
	}
}

func TestRootFileFailures(t *testing.T) {
	vec := vector(t)
	src := string(pretty(t, vec.Get("root_file")))
	set := keys(t, vec)

	// Tampered count: self_hash no longer matches. The signature is over the stated self_hash, so
	// it still verifies — the same split as a receipt's self_hash and signature checks.
	_, checks := root.Verify([]byte(strings.Replace(src, `"count": 3`, `"count": 2`, 1)), set)
	if status(checks, "root_self_hash") != receipt.Fail || status(checks, "root_signature") != receipt.Pass {
		t.Errorf("tampered count: %v", checks)
	}
	// A flipped signature byte fails the signature and nothing else.
	sigAt := strings.Index(src, `"sig": "`) + len(`"sig": "`)
	flipped := src[:sigAt] + "A" + src[sigAt+1:]
	if src[sigAt] == 'A' {
		flipped = src[:sigAt] + "B" + src[sigAt+1:]
	}
	_, checks = root.Verify([]byte(flipped), set)
	if status(checks, "root_self_hash") != receipt.Pass || status(checks, "root_signature") != receipt.Fail {
		t.Errorf("flipped signature: %v", checks)
	}
	// Unpinned root key: the file carries no key, so the signature cannot be checked.
	_, checks = root.Verify([]byte(src), receipt.NewKeySet())
	if status(checks, "root_signature") != receipt.Fail || !strings.Contains(checks[2].Detail, "not pinned") {
		t.Errorf("unpinned: %v", checks)
	}
	if status(checks, "root_self_hash") != receipt.Pass {
		t.Errorf("unpinned: self_hash should still pass: %v", checks)
	}
	// A receipt key under the root id is not a root key.
	receiptOnly, _ := receipt.ParseKeySet([]byte(`[{"key_id":"eb-root-test","purpose":"receipt","public_key":"+OIf8AWG2M/e4fqmltCC+xtj9kmks5fAk3UjznkHRuQ="}]`))
	_, checks = root.Verify([]byte(src), receiptOnly)
	if status(checks, "root_signature") != receipt.Fail {
		t.Errorf("wrong purpose: %v", checks)
	}
	// Schema failures skip the rest.
	for name, bad := range map[string]string{
		"unknown member":  strings.Replace(src, `"count": 3`, `"count": 3, "extra": 1`, 1),
		"wrong kind":      strings.Replace(src, `"kind": "exhibitb.root"`, `"kind": "exhibitb.receipt"`, 1),
		"bad date":        strings.Replace(src, `"date": "2026-09-03"`, `"date": "2026-9-3"`, 1),
		"signature role":  strings.Replace(src, `"alg": "ed25519"`, `"alg": "ed25519", "role": "issuer"`, 1),
		"not json":        "{",
		"top-level array": "[]",
	} {
		file, checks := root.Verify([]byte(bad), set)
		if file != nil || status(checks, "root_schema") != receipt.Fail || status(checks, "root_self_hash") != receipt.Skip || status(checks, "root_signature") != receipt.Skip {
			t.Errorf("%s: %v", name, checks)
		}
	}
	// An empty day: count 0, null seqs, the empty-tree root.
	empty := `{"v":1,"kind":"exhibitb.root","date":"2026-09-04","first_seq":null,"last_seq":null,"count":0,"root":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","prev_root":"` + vec.Get("root_file").Get("root").Str + `","head_hash":"` + vec.Get("root_file").Get("head_hash").Str + `","key_id":"eb-root-test","self_hash":"0000000000000000000000000000000000000000000000000000000000000000","signatures":[]}`
	file, checks := root.Verify([]byte(empty), set)
	if file == nil || status(checks, "root_schema") != receipt.Pass || status(checks, "root_signature") != receipt.Fail {
		t.Errorf("empty day: %v", checks)
	}
}

func TestProofStatuses(t *testing.T) {
	vec := vector(t)
	file, _ := root.Verify(pretty(t, vec.Get("root_file")), keys(t, vec))
	c := root.Inclusion([]byte(`{"status":"pending","roots_at":"2026-09-04T00:05:00Z"}`), file, "x", "y")
	if c.Status != receipt.Warn || !strings.Contains(c.Detail, "2026-09-04T00:05:00Z") {
		t.Errorf("pending: %v", c)
	}
	c = root.Inclusion([]byte(`{"status":"unchained","roots_at":null}`), file, "x", "y")
	if c.Status != receipt.Skip {
		t.Errorf("unchained: %v", c)
	}
	c = root.Inclusion([]byte(`{"status":"weird"}`), file, "x", "y")
	if c.Status != receipt.Fail {
		t.Errorf("unknown status: %v", c)
	}
	c = root.Inclusion([]byte(`not json`), file, "x", "y")
	if c.Status != receipt.Fail || !strings.HasPrefix(c.Detail, "proof: $:") {
		t.Errorf("not json: %v", c)
	}
	p := pretty(t, vec.Get("proofs").Array[0])
	if c := root.Inclusion(p, nil, "x", "y"); c.Status != receipt.Skip {
		t.Errorf("no root file: %v", c)
	}
	if c := root.Inclusion(p, file, "", ""); c.Status != receipt.Skip {
		t.Errorf("no receipt: %v", c)
	}
	// A proof with the API's extra members still reads.
	full := strings.Replace(string(p), `"leaf_index": 0`, `"seq": 1, "date": "2026-09-03", "future_member": true, "leaf_index": 0`, 1)
	if c := root.Inclusion([]byte(full), file, "eb_2m4Kq8Xr7vTb3nHd", vec.Get("proofs").Array[0].Get("self_hash").Str); c.Status != receipt.Pass {
		t.Errorf("full proof: %v", c)
	}
	dated := strings.Replace(string(p), `"leaf_index": 0`, `"date": "2026-09-02", "leaf_index": 0`, 1)
	if c := root.Inclusion([]byte(dated), file, "eb_2m4Kq8Xr7vTb3nHd", vec.Get("proofs").Array[0].Get("self_hash").Str); c.Status != receipt.Fail {
		t.Errorf("wrong date: %v", c)
	}
}
