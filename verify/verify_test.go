package verify_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/20012001amiramir/recheck/canonical"
	"github.com/20012001amiramir/recheck/receipt"
	"github.com/20012001amiramir/recheck/verify"
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

func pretty(t *testing.T, v *canonical.Value) []byte {
	t.Helper()
	out, err := canonical.Pretty(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func keys(t *testing.T, entries ...*canonical.Value) *receipt.KeySet {
	t.Helper()
	set := receipt.NewKeySet()
	for _, e := range entries {
		k, err := receipt.ParseKeySet(pretty(t, e))
		if err != nil {
			t.Fatal(err)
		}
		if err := set.Merge(k); err != nil {
			t.Fatal(err)
		}
	}
	return set
}

func names(checks []receipt.Check) string {
	var out []string
	for _, c := range checks {
		out = append(out, c.Name+":"+c.Status)
	}
	return strings.Join(out, " ")
}

func TestReceiptOnly(t *testing.T) {
	vec := vector(t, "receipt.json")
	rep := verify.Run(pretty(t, vec.Get("receipt")), verify.Options{Keys: keys(t, vec.Get("key"))})
	if !rep.OK || rep.Exit != 0 || rep.FirstFailure != nil || len(rep.Checks) != 5 || len(rep.Refetch) != 0 {
		t.Errorf("%+v", rep)
	}
	if rep.Receipt == nil || rep.Receipt.ID != "eb_2m4Kq8Xr7vTb3nHd" || rep.Receipt.KeyID != "eb-receipt-test" || *rep.Receipt.Seq != 1 {
		t.Errorf("info %+v", rep.Receipt)
	}
	var back map[string]any
	if err := json.Unmarshal(rep.JSON(), &back); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ok", "exit", "checks", "receipt", "first_failure", "refetch"} {
		if _, ok := back[k]; !ok {
			t.Errorf("json lacks %s", k)
		}
	}
	if back["first_failure"] != nil {
		t.Errorf("first_failure %v", back["first_failure"])
	}

	tampered := vec.Get("tampered").Array[0]
	rep = verify.Run(pretty(t, tampered.Get("receipt")), verify.Options{})
	if rep.OK || rep.Exit != 1 || rep.FirstFailure == nil || rep.FirstFailure.Check != "self_hash" {
		t.Errorf("%+v", rep)
	}
	rep = verify.Run([]byte("[]"), verify.Options{})
	if rep.Exit != 1 || rep.Receipt != nil || rep.FirstFailure.Check != "schema" {
		t.Errorf("array: %+v", rep)
	}
	// Info is best effort when the schema fails.
	rep = verify.Run([]byte(strings.Replace(string(pretty(t, vec.Get("receipt"))), `"v": 1,`, `"v": 2,`, 1)), verify.Options{})
	if rep.Receipt == nil || rep.Receipt.ID != "eb_2m4Kq8Xr7vTb3nHd" || rep.Receipt.KeyID != "eb-receipt-test" {
		t.Errorf("best-effort info: %+v", rep.Receipt)
	}
	rep = verify.Run(pretty(t, vec.Get("projection")), verify.Options{Keys: keys(t, vec.Get("key"))})
	if !rep.OK || rep.Exit != 0 {
		t.Errorf("projection: %+v", rep)
	}
}

func TestRootAndProof(t *testing.T) {
	vec := vector(t, "receipt.json")
	rootVec := vector(t, "root.json")
	set := keys(t, vec.Get("key"), rootVec.Get("key"))
	rootFile := pretty(t, rootVec.Get("root_file"))
	proof := pretty(t, rootVec.Get("proofs").Array[0])

	// The receipt vector is not one of root.json's leaves (different id and time), so the proof
	// belongs to another receipt: the root checks pass, inclusion fails on self_hash.
	rep := verify.Run(pretty(t, vec.Get("receipt")), verify.Options{Keys: set, Root: rootFile, Proof: proof})
	want := "schema:pass self_hash:pass signature:pass key_pinned:pass chain_fields:pass root_schema:pass root_self_hash:pass root_signature:pass inclusion:fail"
	if got := names(rep.Checks); got != want || rep.Exit != 1 || rep.FirstFailure.Check != "inclusion" {
		t.Errorf("got %s exit %d", got, rep.Exit)
	}

	// Without the root key pinned, root_signature fails.
	rep = verify.Run(pretty(t, vec.Get("receipt")), verify.Options{Keys: keys(t, vec.Get("key")), Root: rootFile, Proof: proof})
	if rep.Checks[7].Name != "root_signature" || rep.Checks[7].Status != receipt.Fail {
		t.Errorf("%s", names(rep.Checks))
	}

	// One of the pair missing is a warning, not a failure.
	rep = verify.Run(pretty(t, vec.Get("receipt")), verify.Options{Keys: set, Proof: proof})
	if got := names(rep.Checks); got != "schema:pass self_hash:pass signature:pass key_pinned:pass chain_fields:pass inclusion:warn" || rep.Exit != 2 {
		t.Errorf("proof only: %s exit %d", got, rep.Exit)
	}
	rep = verify.Run(pretty(t, vec.Get("receipt")), verify.Options{Keys: set, Root: rootFile})
	if got := names(rep.Checks); !strings.HasSuffix(got, "root_signature:pass inclusion:warn") || rep.Exit != 2 {
		t.Errorf("root only: %s exit %d", got, rep.Exit)
	}
	// A pending proof is a warning too.
	rep = verify.Run(pretty(t, vec.Get("receipt")), verify.Options{Keys: set, Root: rootFile, Proof: []byte(`{"status":"pending","roots_at":"2026-09-04T00:05:00Z"}`)})
	if rep.Checks[8].Status != receipt.Warn || rep.Exit != 2 {
		t.Errorf("pending: %s exit %d", names(rep.Checks), rep.Exit)
	}
	// After a schema failure the inclusion check is skipped, not failed.
	rep = verify.Run([]byte("{}"), verify.Options{Keys: set, Root: rootFile, Proof: proof})
	if rep.Checks[8].Status != receipt.Skip || rep.FirstFailure.Check != "schema" {
		t.Errorf("schema failure: %s", names(rep.Checks))
	}
}

func TestRefetch(t *testing.T) {
	vec := vector(t, "receipt.json")
	src := pretty(t, vec.Get("receipt"))
	const cdn = "https://cdn.example.org/reports/2026/q1.pdf"
	const hash = "a6c96f6533f8bcdb7549fd993b3e14a6af8c7ddf447d5535adde121a5936efde"

	calls := []string{}
	fetch := func(url string) (string, error) {
		calls = append(calls, url)
		if url == cdn {
			return hash, nil
		}
		return "", errors.New("no route")
	}
	rep := verify.Run(src, verify.Options{Keys: keys(t, vec.Get("key")), Refetch: fetch})
	// Claim 1 has a final_url and a content hash; claim 2 has a final_url but no hash (no
	// access); claim 3 has neither. Exactly one fetch.
	if len(calls) != 1 || calls[0] != cdn {
		t.Errorf("fetched %v", calls)
	}
	if len(rep.Refetch) != 1 || rep.Refetch[0].Status != verify.Match || rep.Refetch[0].N != 1 || rep.Refetch[0].URL != cdn {
		t.Errorf("items %+v", rep.Refetch)
	}
	last := rep.Checks[len(rep.Checks)-1]
	if last.Name != "refetch" || last.Status != receipt.Pass || !strings.Contains(last.Detail, "1 of 1") || !strings.Contains(last.Detail, "1 without a recorded content hash") || rep.Exit != 0 {
		t.Errorf("%+v exit %d", last, rep.Exit)
	}

	rep = verify.Run(src, verify.Options{Refetch: func(string) (string, error) { return "00" + hash[2:], nil }})
	if rep.Refetch[0].Status != verify.Changed || rep.Checks[5].Status != receipt.Warn || rep.Exit != 2 || !rep.OK {
		t.Errorf("changed: %+v", rep)
	}
	rep = verify.Run(src, verify.Options{Refetch: func(string) (string, error) { return "", errors.New("dial tcp: timeout") }})
	if rep.Refetch[0].Status != verify.Unreachable || rep.Checks[5].Status != receipt.Warn || rep.Exit != 2 || !strings.Contains(rep.Refetch[0].Detail, "timeout") {
		t.Errorf("unreachable: %+v", rep)
	}
	// Projections have no URLs; refetch is skipped and never called.
	rep = verify.Run(pretty(t, vec.Get("projection")), verify.Options{Refetch: func(string) (string, error) { t.Error("fetched from a projection"); return "", nil }})
	if rep.Checks[5].Status != receipt.Skip {
		t.Errorf("projection: %+v", rep.Checks[5])
	}
	rep = verify.Run([]byte("{}"), verify.Options{Refetch: fetch})
	if rep.Checks[5].Status != receipt.Skip {
		t.Errorf("schema failure: %+v", rep.Checks[5])
	}
}

func TestUsage(t *testing.T) {
	rep := verify.Usage("keys: nope")
	if rep.Exit != 64 || rep.OK || !strings.Contains(string(rep.JSON()), `"error": "keys: nope"`) || !strings.Contains(string(rep.JSON()), `"checks": []`) {
		t.Errorf("%s", rep.JSON())
	}
}
