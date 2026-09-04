package merkle_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/20012001amiramir/recheck/canonical"
	"github.com/20012001amiramir/recheck/merkle"
)

func strings(v *canonical.Value) []string {
	out := make([]string, 0, len(v.Array))
	for _, e := range v.Array {
		out = append(out, e.Str)
	}
	return out
}

func TestVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "spec", "vectors", "merkle.json"))
	if err != nil {
		t.Fatal(err)
	}
	trees, err := canonical.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	sizes := map[int64]bool{}
	for _, tree := range trees.Array {
		size := tree.Get("tree_size").Int
		sizes[size] = true
		leavesHex := strings(tree.Get("leaves"))
		if int64(len(leavesHex)) != size {
			t.Fatalf("size %d: %d leaves", size, len(leavesHex))
		}
		for i, l := range leavesHex {
			want := sha256.Sum256([]byte("exhibitb.vector.leaf." + string(rune('0'+i))))
			if l != hex.EncodeToString(want[:]) {
				t.Errorf("size %d: leaf %d is not sha256(exhibitb.vector.leaf.%d)", size, i, i)
			}
		}
		leaves, ok := merkle.ParseHashes(leavesHex)
		if !ok {
			t.Fatalf("size %d: bad leaf hex", size)
		}
		root := tree.Get("root").Str
		if got := hex.EncodeToString(merkle.Root(leaves)); got != root {
			t.Errorf("size %d: root %s want %s", size, got, root)
		}
		proofs := tree.Get("proofs").Array
		if int64(len(proofs)) != size {
			t.Errorf("size %d: %d proofs", size, len(proofs))
		}
		for _, proof := range proofs {
			index := int(proof.Get("leaf_index").Int)
			if int(proof.Get("tree_size").Int) != int(size) {
				t.Errorf("size %d: proof %d carries tree_size %d", size, index, proof.Get("tree_size").Int)
			}
			wantPath := strings(proof.Get("audit_path"))
			gotPath := merkle.AuditPath(leaves, index)
			if len(gotPath) != len(wantPath) {
				t.Errorf("size %d index %d: path length %d want %d", size, index, len(gotPath), len(wantPath))
				continue
			}
			for i := range gotPath {
				if hex.EncodeToString(gotPath[i]) != wantPath[i] {
					t.Errorf("size %d index %d: path[%d] = %x want %s", size, index, i, gotPath[i], wantPath[i])
				}
			}
			if !merkle.VerifyInclusionHex(leavesHex[index], index, int(size), wantPath, root) {
				t.Errorf("size %d index %d: proof does not verify", size, index)
			}
			// The same path at any other index, or for any other size, rebuilds a different root.
			for other := 0; other < int(size); other++ {
				if other != index && merkle.VerifyInclusionHex(leavesHex[index], other, int(size), wantPath, root) {
					t.Errorf("size %d index %d: verifies at index %d", size, index, other)
				}
			}
			// RFC 6962 binds the tree size only as far as the path shape goes (leaf 0 of a
			// 3-leaf tree runs the same steps under size 4); a size that changes the leaf's
			// depth leaves sn != 0 and fails. The root file's count cross-check covers the rest.
			for _, otherSize := range []int{1, int(size) * 2} {
				if otherSize != int(size) && merkle.VerifyInclusionHex(leavesHex[index], index, otherSize, wantPath, root) {
					t.Errorf("size %d index %d: verifies with tree_size %d", size, index, otherSize)
				}
			}
			if len(wantPath) > 0 {
				flipped := append([]string{}, wantPath...)
				flipped[0] = leavesHex[index] // a wrong sibling
				if merkle.VerifyInclusionHex(leavesHex[index], index, int(size), flipped, root) {
					t.Errorf("size %d index %d: verifies with a wrong sibling", size, index)
				}
			}
			if merkle.VerifyInclusionHex(leavesHex[index], index, int(size), append(append([]string{}, wantPath...), root), root) {
				t.Errorf("size %d index %d: verifies with an extra path entry", size, index)
			}
		}
	}
	for _, want := range []int64{0, 1, 2, 3, 7} {
		if !sizes[want] {
			t.Errorf("vector for size %d missing", want)
		}
	}
}

func TestConstants(t *testing.T) {
	if got := hex.EncodeToString(merkle.EmptyRoot()); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("empty root %s", got)
	}
	leaf := sha256.Sum256([]byte("exhibitb.vector.leaf.0"))
	if got := hex.EncodeToString(merkle.LeafHash(leaf[:])); got != "a5b314a22917a23286ed9706710de30e2267f9ced15b5e57957493b858919ce0" {
		t.Errorf("one-leaf root %s", got)
	}
	for n, k := range map[int]int{2: 1, 3: 2, 4: 2, 5: 4, 7: 4, 8: 4, 9: 8, 1000: 512} {
		if merkle.SplitPoint(n) != k {
			t.Errorf("SplitPoint(%d) = %d want %d", n, merkle.SplitPoint(n), k)
		}
	}
}

func TestRefusals(t *testing.T) {
	h := "a5b314a22917a23286ed9706710de30e2267f9ced15b5e57957493b858919ce0"
	if _, ok := merkle.ParseHash("A5B314A22917A23286ED9706710DE30E2267F9CED15B5E57957493B858919CE0"); ok {
		t.Error("uppercase hex must be refused")
	}
	if _, ok := merkle.ParseHash(h[:63]); ok {
		t.Error("63 digits must be refused")
	}
	if _, ok := merkle.ParseHash(h[:63] + "g"); ok {
		t.Error("non-hex must be refused")
	}
	if merkle.VerifyInclusionHex(h, 0, 0, nil, h) || merkle.VerifyInclusionHex(h, -1, 1, nil, h) || merkle.VerifyInclusionHex(h, 1, 1, nil, h) {
		t.Error("index/size outside the tree must be refused")
	}
	if merkle.VerifyInclusionHex(h, 0, 1, []string{"zz"}, h) || merkle.VerifyInclusionHex("zz", 0, 1, nil, h) || merkle.VerifyInclusionHex(h, 0, 1, nil, "zz") {
		t.Error("non-hex values must be refused")
	}
	if _, ok := merkle.RootHex([]string{h, "nope"}); ok {
		t.Error("RootHex must refuse a bad leaf")
	}
}
