package canonical_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/20012001amiramir/recheck/canonical"
)

func loadVector(t *testing.T, name string) *canonical.Value {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "spec", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	v, err := canonical.Parse(data)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return v
}

func TestCanonicalVectors(t *testing.T) {
	cases := loadVector(t, "canonical.json")
	if cases.Kind != canonical.Array || len(cases.Array) < 15 {
		t.Fatalf("expected at least 15 cases, got %d", len(cases.Array))
	}
	for _, c := range cases.Array {
		name := c.Get("name").Str
		want := c.Get("canonical").Str
		got, err := canonical.Canonicalize(c.Get("input"))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s:\n got %s\nwant %s", name, got, want)
		}
		// Parsing the canonical bytes and canonicalizing again must be a fixed point.
		again, err := canonical.Parse(got)
		if err != nil {
			t.Errorf("%s: reparse: %v", name, err)
			continue
		}
		got2, err := canonical.Canonicalize(again)
		if err != nil || string(got2) != want {
			t.Errorf("%s: not a fixed point: %s (%v)", name, got2, err)
		}
	}
}

func TestSelfHashVectors(t *testing.T) {
	cases := loadVector(t, "selfhash.json")
	if len(cases.Array) < 4 {
		t.Fatalf("expected at least 4 cases, got %d", len(cases.Array))
	}
	for _, c := range cases.Array {
		name := c.Get("name").Str
		got, err := canonical.SelfHash(c.Get("input"))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if want := c.Get("self_hash").Str; got != want {
			t.Errorf("%s: got %s want %s", name, got, want)
		}
	}
}

func canon(t *testing.T, src string) (string, error) {
	t.Helper()
	v, err := canonical.Parse([]byte(src))
	if err != nil {
		return "", err
	}
	out, err := canonical.Canonicalize(v)
	return string(out), err
}

func TestNumbersByValue(t *testing.T) {
	ok := map[string]string{
		`{"a":812004.0}`:            `{"a":812004}`,
		`{"a":8.12004e5}`:           `{"a":812004}`,
		`{"a":-0}`:                  `{"a":0}`,
		`{"a":-0.0}`:                `{"a":0}`,
		`{"a":0}`:                   `{"a":0}`,
		`{"a":1E2}`:                 `{"a":100}`,
		`{"a":9007199254740991}`:    `{"a":9007199254740991}`,
		`{"a":-9007199254740991}`:   `{"a":-9007199254740991}`,
		`{"a":9007199254740991.0}`:  `{"a":9007199254740991}`,
		`{"a":90071992547409910e-1}`: `{"a":9007199254740991}`,
	}
	for src, want := range ok {
		got, err := canon(t, src)
		if err != nil || got != want {
			t.Errorf("%s: got %q (%v) want %q", src, got, err, want)
		}
	}
	bad := []string{
		`{"a":0.93}`,
		`{"a":1e400}`,
		`{"a":-1e400}`,
		`{"a":9007199254740992}`,
		`{"a":-9007199254740992}`,
		`{"a":1.5e0}`,
	}
	for _, src := range bad {
		_, err := canon(t, src)
		var ce *canonical.Error
		if !errors.As(err, &ce) || ce.Msg != "non-integer number" || ce.Path != "$.a" {
			t.Errorf("%s: want non-integer number at $.a, got %v", src, err)
		}
	}
	// A bad number token is a parse error, not a value.
	for _, src := range []string{`{"a":01}`, `{"a":1.}`, `{"a":.5}`, `{"a":+1}`, `{"a":1e}`, `{"a":-}`, `{"a":0x10}`, `{"a":NaN}`, `{"a":Infinity}`} {
		if _, err := canonical.Parse([]byte(src)); err == nil {
			t.Errorf("%s: expected a parse error", src)
		}
	}
}

func TestStrictParsing(t *testing.T) {
	refuse := map[string]string{
		`{"a":1,"a":2}`:                 `duplicate key "a" at $`,
		`{"o":{"x":1,"x":1}}`:           `duplicate key "x" at $.o`,
		`{"a":"\ud800"}`:                "unpaired surrogate at $.a",
		`{"a":"\udc00"}`:                "unpaired surrogate at $.a",
		`{"a":"\ud83dx"}`:               "unpaired surrogate at $.a",
		`{"a":"\ud83d\u0041"}`:          "unpaired surrogate at $.a",
		`["\udfff"]`:                    "unpaired surrogate at $[0]",
		`{"\ud800":1}`:                  "unpaired surrogate at $",
		"{\"a\":\"\xed\xa0\x80\"}":      "unpaired surrogate at $.a",
		"{\"a\":\"\xff\"}":              "invalid UTF-8 at $.a",
		"{\"a\":\"\xc0\xaf\"}":          "invalid UTF-8 at $.a",
		"\xef\xbb\xbf{}":                "byte-order mark is not JSON at $",
		"{\"a\":\"x\ty\"}":              "control character in string at $.a",
		`{"a":1,}`:                      "expected a string key at $",
		`[1,]`:                          "unexpected character ']' at $[1]",
		`{} x`:                          "unexpected content after the value at $",
		`{}{}`:                          "unexpected content after the value at $",
		``:                              "empty input at $",
		`   `:                           "empty input at $",
		`{"a":"\x"}`:                    `invalid escape \x at $.a`,
		`{"a":"\u12"}`:                  `invalid \u escape at $.a`,
		`{"a":tru}`:                     "invalid literal at $.a",
		`{"a"`:                          "expected ':' after a key at $",
		`{"a":1`:                        "expected ',' or '}' at $",
		`[1 2]`:                         "expected ',' or ']' at $",
		`"unterminated`:                 "unterminated string at $",
		"{\"a\":1}\n\u00a0":             "unexpected content after the value at $",
	}
	for src, want := range refuse {
		_, err := canonical.Parse([]byte(src))
		if err == nil || err.Error() != want {
			t.Errorf("%q: got %v, want %q", src, err, want)
		}
	}
	// Deep nesting is refused rather than overflowing the stack.
	deep := strings.Repeat("[", 5000) + strings.Repeat("]", 5000)
	if _, err := canonical.Parse([]byte(deep)); err == nil || !strings.Contains(err.Error(), "nesting deeper") {
		t.Errorf("deep nesting: got %v", err)
	}
}

func TestAcceptsWhatJSONAllows(t *testing.T) {
	cases := map[string]string{
		"  {\r\n\t\"b\" : [ 1 , true , null , \"x\" ] , \"a\" : {} }  ": `{"a":{},"b":[1,true,null,"x"]}`,
		`{"a":"\/\u0041\u00e9\ud83d\ude00"}`:                             `{"a":"/Aé😀"}`,
		"{\"a\":\"\u007f\u0080\u2028\u2029\"}":                             "{\"a\":\"\u007f\u0080\u2028\u2029\"}",
		`{"a":"\u001b\u0000\u001F"}`:                                      `{"a":"\u001b\u0000\u001f"}`,
		`{"10":1,"9":2,"1":3}`:                                            `{"1":3,"10":1,"9":2}`,
		`{"b":{"z":1,"a":2},"a":[{"y":1,"x":2}]}`:                         `{"a":[{"x":2,"y":1}],"b":{"a":2,"z":1}}`,
		`[]`:                                                              `[]`,
		`"top-level string"`:                                              `"top-level string"`,
		`12`:                                                              `12`,
		`null`:                                                            `null`,
	}
	for src, want := range cases {
		got, err := canon(t, src)
		if err != nil || got != want {
			t.Errorf("%q: got %q (%v) want %q", src, got, err, want)
		}
	}
}

func TestGoValues(t *testing.T) {
	got, err := canonical.Canonicalize(map[string]any{
		"b": int64(1),
		"a": []any{true, nil, "x\n", 3, float64(4)},
		"😀": map[string]any{},
		"":  false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"":false,"a":[true,null,"x\n",3,4],"b":1,"😀":{}}`; string(got) != want {
		t.Errorf("got %s want %s", got, want)
	}
	for _, bad := range []any{map[string]any{"a": 0.5}, map[string]any{"a": float64(1 << 53)}, map[string]any{"a": int64(1<<53 + 1)}, map[string]any{"a": "\xff"}, map[string]any{"a": uint8(1)}} {
		if _, err := canonical.Canonicalize(bad); err == nil {
			t.Errorf("%v: expected an error", bad)
		}
	}
	h, err := canonical.SelfHash(map[string]any{"a": 1, "self_hash": "x", "signatures": []any{1}})
	if err != nil || h != "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862" {
		t.Errorf("SelfHash over a map: %s %v", h, err)
	}
	if _, err := canonical.SelfHash([]any{}); err == nil {
		t.Error("SelfHash of an array must fail")
	}
}

func TestPrettyRoundTrip(t *testing.T) {
	src := `{"z":[1,{"b":"x\u0001","a":null}],"a":{},"e":[]}`
	v, err := canonical.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	out, err := canonical.Pretty(v)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"z\": [\n    1,\n    {\n      \"b\": \"x\\u0001\",\n      \"a\": null\n    }\n  ],\n  \"a\": {},\n  \"e\": []\n}\n"
	if string(out) != want {
		t.Errorf("pretty:\n%s\nwant\n%s", out, want)
	}
	again, err := canonical.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	c1, _ := canonical.Canonicalize(v)
	c2, _ := canonical.Canonicalize(again)
	if string(c1) != string(c2) {
		t.Errorf("pretty output changed the value: %s vs %s", c1, c2)
	}
}

func TestOffsets(t *testing.T) {
	src := `{"a": [1, "two"], "b": {"c": true}}`
	v, err := canonical.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if v.Offset != 0 || v.End != len(src) {
		t.Errorf("root span %d..%d", v.Offset, v.End)
	}
	two := v.Get("a").Array[1]
	if src[two.Offset:two.End] != `"two"` {
		t.Errorf("string span %q", src[two.Offset:two.End])
	}
	c := v.Get("b").Get("c")
	if src[c.Offset:c.End] != "true" {
		t.Errorf("literal span %q", src[c.Offset:c.End])
	}
	if v.Members[1].KeyOffset != strings.Index(src, `"b"`) {
		t.Errorf("key offset %d", v.Members[1].KeyOffset)
	}
	if v.Get("nope") != nil || two.Get("x") != nil {
		t.Error("Get on a missing member or a non-object must be nil")
	}
}
