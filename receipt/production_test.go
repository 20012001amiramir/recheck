package receipt_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/20012001amiramir/recheck/receipt"
)

// The shapes the issuer serves today, verified by the build in this checkout.
//
// This is the regression for the defect that shipped: a wasm built before the case registry's
// members reached the format refused ten of the issuer's own twenty-one receipts as
// `$.claims[…].exists.registry.name_check: unknown member`, and, because the schema check was
// fail-closed and stopped everything after it, never looked at the signatures at all.
//
// Two of these files are what `GET /api/receipt/<id>` served on 2026-09-09; the third is the shape
// the registry's name comparison produces, signed with the fixture key so it can be checked with no
// network. Refresh the live pair with, from the repository root:
//
//	curl -sS https://exhibitb.autofract.com/api/receipt/eb_gDPTixajtKB22wym \
//	  -o receipt/testdata/production/eb_gDPTixajtKB22wym.json
//
// and copy the same bytes into the app's tests/fixtures/production/.
//
// Every one of them must verify, and — the part that would have caught the defect — check 1 must be
// `pass`, not `warn`: a member this build does not know is a member the app can seal and this
// verifier cannot read, and the two are meant to move together. When a new field is added to the
// format, refreshing these files fails here rather than in a reader's hands.
func TestProductionShapes(t *testing.T) {
	dir := filepath.Join("testdata", "production")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		seen++
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		// No key set: these carry the production issuer key, which no test pins. Check 3 verifies
		// against the key inside the record, which is what a stranger with this tool and no network
		// can establish, and key_pinned skips.
		res := receipt.Verify(data, nil)
		if !res.OK() || receipt.ExitCode(res.Checks) != 0 {
			t.Errorf("%s: ok=%v exit=%d %v", e.Name(), res.OK(), receipt.ExitCode(res.Checks), res.Checks)
			continue
		}
		if res.Checks[0].Status != receipt.Pass {
			t.Errorf("%s: schema %s — this build does not know every member the issuer serves: %s", e.Name(), res.Checks[0].Status, res.Checks[0].Detail)
		}
		if res.Receipt == nil || len(res.Receipt.SchemaWarnings) != 0 {
			t.Errorf("%s: %d unknown members in a live shape", e.Name(), len(res.Receipt.SchemaWarnings))
		}
		// The two live files are projections; the third is one too. Check 3 is the whole point.
		sig := res.Checks[2]
		if sig.Name != "projection_signature" || sig.Status != receipt.Pass {
			t.Errorf("%s: %s is %s (%s)", e.Name(), sig.Name, sig.Status, sig.Detail)
		}
	}
	if seen < 3 {
		t.Fatalf("%d production shapes on disk, want at least 3", seen)
	}
}

// TestProductionRegistryMembers is the same defect stated as a member list: the case registry's
// answer, which the shipped build had never heard of, must be read to its shape rather than
// refused.
func TestProductionRegistryMembers(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "production", "eb_6tLd4vXq9BnR2sKw.json"))
	if err != nil {
		t.Fatal(err)
	}
	res := receipt.Verify(data, nil)
	if res.Receipt == nil {
		t.Fatalf("did not parse: %v", res.Checks)
	}
	reg := res.Receipt.Claims[1].Exists.Registry
	if reg == nil {
		t.Fatal("claim 2 carries no registry")
	}
	if reg.NameCheck == nil || *reg.NameCheck != "mismatch" {
		t.Errorf("name_check %v, want mismatch", reg.NameCheck)
	}
	if reg.Reason == nil || *reg.Reason != "citation_belongs_to_another_case" {
		t.Errorf("reason %v", reg.Reason)
	}
	if reg.Method == nil || *reg.Method != "name_search" {
		t.Errorf("method %v", reg.Method)
	}
	// A projection carries no cluster_id (§11), and its absence is not a complaint.
	if reg.ClusterID != nil {
		t.Errorf("a projection must not carry cluster_id: %v", reg.ClusterID)
	}
}
