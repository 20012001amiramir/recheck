package tamper_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/20012001amiramir/recheck/canonical"
	"github.com/20012001amiramir/recheck/tamper"
)

func receiptText(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "spec", "vectors", "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := canonical.ParseLenient(data)
	if err != nil {
		t.Fatal(err)
	}
	out, err := canonical.Pretty(v.Get("receipt"))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestSingleByteEdit(t *testing.T) {
	src := receiptText(t)
	needle := `"overlap_bp": 10000`
	at := strings.Index(src, needle)
	edited := src[:at+len(needle)-1] + "1" + src[at+len(needle):]
	rep := tamper.Tamper(src, edited)
	wantOffset := at + len(needle) - 1
	if !rep.Changed || rep.Offset != wantOffset || rep.InvalidJSON || rep.WhitespaceOnly {
		t.Fatalf("report %+v, want offset %d", rep, wantOffset)
	}
	wantLine := 1 + strings.Count(src[:wantOffset], "\n")
	wantCol := wantOffset - strings.LastIndex(src[:wantOffset], "\n")
	if rep.Line != wantLine || rep.Col != wantCol {
		t.Errorf("line %d col %d, want %d %d", rep.Line, rep.Col, wantLine, wantCol)
	}
	if rep.Path != "/claims/0/says/overlap_bp" {
		t.Errorf("path %q", rep.Path)
	}
}

func TestPaths(t *testing.T) {
	src := receiptText(t)
	parsed, _ := canonical.Parse([]byte(src))
	sig := parsed.Get("signatures").Array[0].Get("sig").Str
	flipped := "B" + sig[1:]
	if sig[0] == 'B' {
		flipped = "A" + sig[1:]
	}
	cases := map[string]struct {
		from, to, path string
	}{
		"top-level string": {`"kind": "exhibitb.receipt"`, `"kind": "exhibitb.receipt.v2"`, "/kind"},
		"nested string":    {`"verdict": "MATCH"`, `"verdict": "DRIFT"`, "/claims/0/says/verdict"},
		"array element":    {`120,`, `121,`, "/claims/0/doc_span/0"},
		"null to value":    {`"dissent": null`, `"dissent": true`, "/claims/0/dissent"},
		"member removed":   {`"n": 1,`, ``, "/claims/0/n"},
		"member added":     {`"n": 1,`, `"n": 1, "x": 1,`, "/claims/0/x"},
		"member renamed":   {`"overlap_bp": 10000`, `"overlap_bq": 10000`, "/claims/0/says"},
		"two members":      {`"n": 1,`, `"n": 2, "claim_hmac_": 1,`, "/claims/0"},
		"array shortened":  {`"retrievers": [`, `"retrievers": [{"id":"A","vantage":"origin","status":200,"content_sha256":null},`, "/claims/0/exists/retrievers"},
		"signature":        {sig, flipped, "/signatures/0/sig"},
		"type change":      {`"seq": 1,`, `"seq": "1",`, "/seq"},
		"key with a slash": {`"v": 1,`, `"v": 1, "a/b~c": 1,`, "/a~1b~0c"},
	}
	for name, c := range cases {
		if !strings.Contains(src, c.from) {
			t.Fatalf("%s: %q not in the receipt", name, c.from)
		}
		edited := strings.Replace(src, c.from, c.to, 1)
		rep := tamper.Tamper(src, edited)
		if !rep.Changed || rep.InvalidJSON || rep.WhitespaceOnly || rep.Path != c.path {
			t.Errorf("%s: %+v, want path %s", name, rep, c.path)
		}
		if rep.Offset != strings.Index(src, c.from)+firstDiff(c.from, c.to) {
			t.Errorf("%s: offset %d", name, rep.Offset)
		}
	}
}

func firstDiff(a, b string) int {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	return i
}

func TestWhitespaceOnly(t *testing.T) {
	src := receiptText(t)
	compact, _ := canonical.Canonicalize(func() *canonical.Value { v, _ := canonical.Parse([]byte(src)); return v }())
	for name, edited := range map[string]string{
		"extra newline":     strings.Replace(src, `"v": 1,`, "\"v\": 1,\n", 1),
		"tabs":              strings.ReplaceAll(src, "  ", "\t"),
		"canonical bytes":   string(compact),
		"number respelled":  strings.Replace(src, `"bytes": 812004,`, `"bytes": 8.12004e5,`, 1),
		"members reordered": strings.Replace(strings.Replace(src, `"v": 1,`, `"kind": "exhibitb.receipt", "v": 1,`, 1), `  "kind": "exhibitb.receipt",`, ``, 1),
	} {
		rep := tamper.Tamper(src, edited)
		if !rep.Changed || !rep.WhitespaceOnly || rep.InvalidJSON || rep.Path != "" {
			t.Errorf("%s: %+v", name, rep)
		}
	}
}

func TestInvalidAndIdentical(t *testing.T) {
	src := receiptText(t)
	rep := tamper.Tamper(src, src)
	if rep.Changed || rep.Offset != -1 || rep.InvalidJSON || rep.WhitespaceOnly {
		t.Errorf("identical: %+v", rep)
	}
	for name, edited := range map[string]string{
		"brace removed":     strings.TrimSuffix(strings.TrimSpace(src), "}"),
		"lone surrogate":    strings.Replace(src, `"extractor": "unpdf@1"`, `"extractor": "\ud800"`, 1),
		"duplicate key":     strings.Replace(src, `"v": 1,`, `"v": 1, "v": 1,`, 1),
		"trailing garbage":  src + "x",
		"empty":             "",
		"truncated in text": src[:len(src)/2],
	} {
		rep := tamper.Tamper(src, edited)
		if !rep.Changed || !rep.InvalidJSON || rep.Path != "" || rep.WhitespaceOnly {
			t.Errorf("%s: %+v", name, rep)
		}
		if rep.Offset < 0 || rep.Line < 1 || rep.Col < 1 {
			t.Errorf("%s: position %+v", name, rep)
		}
	}
	// A non-integer edit is not invalid JSON, just a changed number.
	rep = tamper.Tamper(src, strings.Replace(src, `"overlap_bp": 10000`, `"overlap_bp": 10000.5`, 1))
	if rep.InvalidJSON || rep.WhitespaceOnly || rep.Path != "/claims/0/says/overlap_bp" {
		t.Errorf("non-integer: %+v", rep)
	}
}

func TestColumnsCountUTF16(t *testing.T) {
	orig := "{\"a\": \"é😀x\"}"
	edited := "{\"a\": \"é😀y\"}"
	rep := tamper.Tamper(orig, edited)
	// é is 2 bytes, 😀 is 4 bytes: the x sits at byte 7+2+4 = 13 and at UTF-16 column 1+7+1+2 = 11.
	if rep.Offset != 13 || rep.Line != 1 || rep.Col != 11 || rep.Path != "/a" {
		t.Errorf("%+v", rep)
	}
	rep = tamper.Tamper("{\n\"a\":\n[1,\n2]}", "{\n\"a\":\n[1,\n3]}")
	if rep.Line != 4 || rep.Col != 1 || rep.Offset != 11 || rep.Path != "/a/1" {
		t.Errorf("%+v", rep)
	}
}
