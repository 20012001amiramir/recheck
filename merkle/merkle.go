// Package merkle is the RFC 6962 §2.1 hash tree of spec/RECEIPT.md §8 and the inclusion-proof
// check of §10. Leaf data for a receipt is the 32 raw bytes of its self_hash.
package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
)

// HashSize is the size of every node, leaf datum and root in bytes.
const HashSize = sha256.Size

var (
	leafPrefix = []byte{0x00}
	nodePrefix = []byte{0x01}
)

// EmptyRoot is MTH({}): sha256 of the empty string.
func EmptyRoot() []byte {
	s := sha256.Sum256(nil)
	return s[:]
}

// LeafHash is sha256(0x00 ‖ leaf).
func LeafHash(leaf []byte) []byte {
	h := sha256.New()
	h.Write(leafPrefix)
	h.Write(leaf)
	return h.Sum(nil)
}

// NodeHash is sha256(0x01 ‖ left ‖ right).
func NodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write(nodePrefix)
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// SplitPoint is the largest power of two strictly less than n, for n > 1.
func SplitPoint(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// Root is MTH over the leaves in order.
func Root(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		return EmptyRoot()
	case 1:
		return LeafHash(leaves[0])
	}
	k := SplitPoint(len(leaves))
	return NodeHash(Root(leaves[:k]), Root(leaves[k:]))
}

// AuditPath is PATH(index, leaves) of spec §10, ordered from the leaf upward: the first entry is
// the hash of the leaf's sibling subtree. It is empty for a one-leaf tree. index must be within
// the tree.
func AuditPath(leaves [][]byte, index int) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := SplitPoint(len(leaves))
	if index < k {
		return append(AuditPath(leaves[:k], index), Root(leaves[k:]))
	}
	return append(AuditPath(leaves[k:], index-k), Root(leaves[:k]))
}

// VerifyInclusion rebuilds the root from the leaf data, its index, the tree size and the audit
// path (RFC 9162 §2.1.3.2) and reports whether it equals root. A path the tree cannot have, an
// index outside the tree or a wrong-sized hash is false, never an error.
func VerifyInclusion(leaf []byte, index, size int, path [][]byte, root []byte) bool {
	if index < 0 || size < 1 || index >= size || len(root) != HashSize {
		return false
	}
	for _, p := range path {
		if len(p) != HashSize {
			return false
		}
	}
	fn, sn := index, size-1
	r := LeafHash(leaf)
	for _, p := range path {
		if sn == 0 {
			return false
		}
		if fn%2 == 1 || fn == sn {
			r = NodeHash(p, r)
			for fn != 0 && fn%2 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(r, root)
}

// ParseHash decodes a hex64 string (64 lowercase hex digits). Uppercase is refused, as the spec
// never produces it.
func ParseHash(s string) ([]byte, bool) {
	if len(s) != 2*HashSize {
		return nil, false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, false
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

// ParseHashes decodes a list of hex64 strings; false if any is not hex64.
func ParseHashes(ss []string) ([][]byte, bool) {
	out := make([][]byte, 0, len(ss))
	for _, s := range ss {
		b, ok := ParseHash(s)
		if !ok {
			return nil, false
		}
		out = append(out, b)
	}
	return out, true
}

// RootHex is Root over hex64 leaves, as hex64.
func RootHex(leaves []string) (string, bool) {
	bs, ok := ParseHashes(leaves)
	if !ok {
		return "", false
	}
	return hex.EncodeToString(Root(bs)), true
}

// VerifyInclusionHex is VerifyInclusion over hex64 values; any value that is not hex64 is false.
func VerifyInclusionHex(leaf string, index, size int, path []string, root string) bool {
	l, ok := ParseHash(leaf)
	if !ok {
		return false
	}
	ps, ok := ParseHashes(path)
	if !ok {
		return false
	}
	r, ok := ParseHash(root)
	if !ok {
		return false
	}
	return VerifyInclusion(l, index, size, ps, r)
}
