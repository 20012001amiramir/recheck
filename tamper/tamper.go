// Package tamper locates the first difference between two receipt texts: the byte offset, its
// line and column, and the JSON pointer of the innermost value that changed. It is pure — the
// tamper playground on the landing page runs it in the browser.
package tamper

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/20012001amiramir/recheck/canonical"
)

// Report describes how edited differs from original.
type Report struct {
	// Changed is false when the two texts are byte-identical.
	Changed bool `json:"changed"`
	// Offset is the first differing byte, -1 when identical.
	Offset int `json:"offset"`
	// Line and Col locate Offset: both 1-based, Col in UTF-16 code units from the start of the
	// line, so an editor can place a cursor on it.
	Line int `json:"line"`
	Col  int `json:"col"`
	// Path is the JSON pointer (RFC 6901) of the innermost changed value when both texts parse:
	// "" is the root, "/claims/3/says/verdict" a member. Empty when it cannot be determined.
	Path string `json:"path"`
	// WhitespaceOnly is true when the canonical forms are equal: whitespace, member order or a
	// number's spelling changed, nothing that any hash sees.
	WhitespaceOnly bool `json:"whitespace_only"`
	// InvalidJSON is true when either text does not parse under the spec's rules (§1.9).
	InvalidJSON bool `json:"invalid_json"`
}

// Tamper compares two texts.
func Tamper(original, edited string) Report {
	if original == edited {
		return Report{Offset: -1, Line: 0, Col: 0}
	}
	offset := firstDifference(original, edited)
	line, col := position(original[:offset])
	rep := Report{Changed: true, Offset: offset, Line: line, Col: col}

	a, errA := canonical.Parse([]byte(original))
	b, errB := canonical.Parse([]byte(edited))
	if errA != nil || errB != nil {
		rep.InvalidJSON = true
		return rep
	}
	ca, errCA := canonical.Canonicalize(a)
	cb, errCB := canonical.Canonicalize(b)
	if errCA == nil && errCB == nil && string(ca) == string(cb) {
		rep.WhitespaceOnly = true
		return rep
	}
	if p, changed := diff(a, b, ""); changed {
		rep.Path = p
	}
	return rep
}

func firstDifference(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// position is the 1-based line and UTF-16 column just past prefix.
func position(prefix string) (int, int) {
	line := 1 + strings.Count(prefix, "\n")
	last := prefix
	if i := strings.LastIndexByte(prefix, '\n'); i >= 0 {
		last = prefix[i+1:]
	}
	col := 1
	for len(last) > 0 {
		r, size := utf8.DecodeRuneInString(last)
		if r >= 0x10000 {
			col += 2
		} else {
			col++
		}
		last = last[size:]
	}
	return line, col
}

func escapePointer(key string) string {
	return strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
}

// diff returns the pointer of the innermost value that differs between a and b, and whether
// anything differs at all. When several children changed, the parent is the answer.
func diff(a, b *canonical.Value, ptr string) (string, bool) {
	if a.Kind != b.Kind {
		return ptr, true
	}
	switch a.Kind {
	case canonical.Null:
		return "", false
	case canonical.Bool:
		return ptr, a.Bool != b.Bool
	case canonical.Number:
		if a.IsInt && b.IsInt {
			return ptr, a.Int != b.Int
		}
		return ptr, a.Literal != b.Literal
	case canonical.String:
		return ptr, a.Str != b.Str
	case canonical.Array:
		if len(a.Array) != len(b.Array) {
			return ptr, true
		}
		var changed []string
		for i := range a.Array {
			if p, c := diff(a.Array[i], b.Array[i], ptr+"/"+strconv.Itoa(i)); c {
				changed = append(changed, p)
			}
		}
		return one(ptr, changed)
	case canonical.Object:
		var changed []string
		seen := map[string]bool{}
		for _, m := range a.Members {
			seen[m.Key] = true
			other := b.Get(m.Key)
			if other == nil {
				changed = append(changed, ptr+"/"+escapePointer(m.Key))
				continue
			}
			if p, c := diff(m.Value, other, ptr+"/"+escapePointer(m.Key)); c {
				changed = append(changed, p)
			}
		}
		for _, m := range b.Members {
			if !seen[m.Key] {
				changed = append(changed, ptr+"/"+escapePointer(m.Key))
			}
		}
		return one(ptr, changed)
	}
	return ptr, true
}

func one(parent string, changed []string) (string, bool) {
	switch len(changed) {
	case 0:
		return "", false
	case 1:
		return changed[0], true
	default:
		return parent, true
	}
}
