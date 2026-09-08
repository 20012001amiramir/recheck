package cli_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/20012001amiramir/recheck/canonical"
	"github.com/20012001amiramir/recheck/cli"
)

type run struct {
	code   int
	stdout string
	stderr string
}

func exec(t *testing.T, stdin string, args ...string) run {
	t.Helper()
	var out, errb bytes.Buffer
	code := cli.Main(args, strings.NewReader(stdin), &out, &errb)
	return run{code, out.String(), errb.String()}
}

// fixtures writes the vector receipt, projection, tampered copy, key set, root file and proof
// into a temp dir and returns their paths.
func fixtures(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	paths := map[string]string{}
	write := func(name string, v *canonical.Value) {
		out, err := canonical.Pretty(v)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, out, 0o644); err != nil {
			t.Fatal(err)
		}
		paths[name] = p
	}
	load := func(name string) *canonical.Value {
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
	rv := load("receipt.json")
	write("receipt.json", rv.Get("receipt"))
	write("projection.json", rv.Get("projection"))
	write("projection_tampered.json", rv.Get("projection_tampered").Get("receipt"))
	write("unchained.json", rv.Get("unchained").Get("receipt"))
	write("tampered.json", rv.Get("tampered").Array[0].Get("receipt"))
	write("surrogate.json", rv.Get("tampered").Array[3].Get("receipt"))
	write("legacy.json", rv.Get("legacy").Get("receipt"))
	write("legacy-projection.json", rv.Get("legacy").Get("projection"))
	rootV := load("root.json")
	write("root.json", rootV.Get("root_file"))
	write("proof.json", rootV.Get("proofs").Array[0])
	keys := `[` + string(mustPretty(t, rv.Get("key"))) + `,` + string(mustPretty(t, rootV.Get("key"))) + `]`
	paths["keys.json"] = filepath.Join(dir, "keys.json")
	os.WriteFile(paths["keys.json"], []byte(keys), 0o644)
	paths["test-key.json"] = filepath.Join("..", "spec", "vectors", "test-key.json")
	paths["dir"] = dir
	return paths
}

func mustPretty(t *testing.T, v *canonical.Value) []byte {
	t.Helper()
	out, err := canonical.Pretty(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifyExitCodes(t *testing.T) {
	f := fixtures(t)
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"valid with pinned fixture key", []string{"verify", f["receipt.json"], "--keys", f["keys.json"]}, 0, "RESULT: PASS"},
		{"test-key.json works as a key set", []string{"verify", f["receipt.json"], "--keys", f["test-key.json"]}, 0, "RESULT: PASS"},
		{"valid, key unknown to the pinned set", []string{"verify", f["receipt.json"]}, 2, "issuer key not pinned"},
		{"offline is a no-op", []string{"verify", f["receipt.json"], "--offline", "--keys", f["keys.json"]}, 0, "RESULT: PASS"},
		{"projection", []string{"verify", f["projection.json"], "--keys", f["keys.json"]}, 0, "RESULT: PASS"},
		{"projection, its own signature checked", []string{"verify", f["projection.json"], "--keys", f["keys.json"], "--ascii"}, 0, "+ projection_signature"},
		{"projection an attacker rewrote", []string{"verify", f["projection_tampered.json"], "--keys", f["keys.json"]}, 1, "projection_sig does not verify"},
		{"unchained", []string{"verify", f["unchained.json"], "--keys", f["keys.json"]}, 0, "not anchored to the public chain"},
		{"a body sealed before the format was finalized", []string{"verify", f["legacy.json"], "--keys", f["keys.json"]}, 0, "RESULT: PASS"},
		{"its projection", []string{"verify", f["legacy-projection.json"], "--keys", f["keys.json"]}, 0, "RESULT: PASS"},
		{"tampered", []string{"verify", f["tampered.json"], "--keys", f["keys.json"]}, 1, "RESULT: FAIL"},
		{"lone surrogate", []string{"verify", f["surrogate.json"], "--keys", f["keys.json"]}, 1, "unpaired surrogate"},
		{"root and proof for another receipt", []string{"verify", f["receipt.json"], "--keys", f["keys.json"], "--root", f["root.json"], "--proof", f["proof.json"]}, 1, "inclusion"},
		{"proof without root", []string{"verify", f["receipt.json"], "--keys", f["keys.json"], "--proof", f["proof.json"]}, 2, "without its root file"},
		{"ascii markers", []string{"verify", f["receipt.json"], "--keys", f["keys.json"], "--ascii"}, 0, "+ schema"},
		{"flag before file", []string{"verify", "--keys", f["keys.json"], f["receipt.json"]}, 0, "RESULT: PASS"},
		{"flag with equals", []string{"verify", "--keys=" + f["keys.json"], f["receipt.json"]}, 0, "RESULT: PASS"},
	}
	for _, c := range cases {
		r := exec(t, "", c.args...)
		if r.code != c.code || !strings.Contains(r.stdout, c.want) {
			t.Errorf("%s: exit %d\nstdout: %s\nstderr: %s", c.name, r.code, r.stdout, r.stderr)
		}
	}
	// Markers are ASCII when stdout is not a terminal (a buffer here), per the contract.
	r := exec(t, "", "verify", f["receipt.json"], "--keys", f["keys.json"])
	if !strings.Contains(r.stdout, "+ schema") || !strings.Contains(r.stdout, "receipt eb_2m4Kq8Xr7vTb3nHd | seq 1 | issued 2026-09-03T11:22:44Z | key eb-receipt-test") {
		t.Errorf("human output:\n%s", r.stdout)
	}
}

func TestVerifyUsage(t *testing.T) {
	f := fixtures(t)
	cases := []struct {
		name string
		args []string
	}{
		{"no args", nil},
		{"unknown command", []string{"frobnicate"}},
		{"missing file", []string{"verify", filepath.Join(f["dir"], "nope.json")}},
		{"unknown flag", []string{"verify", f["receipt.json"], "--verbose"}},
		{"two files", []string{"verify", f["receipt.json"], f["receipt.json"]}},
		{"keys flag without value", []string{"verify", f["receipt.json"], "--keys"}},
		{"bad keys file", []string{"verify", f["receipt.json"], "--keys", f["receipt.json"]}},
		{"offline id", []string{"verify", "eb_2m4Kq8Xr7vTb3nHd", "--offline"}},
		{"offline and refetch", []string{"verify", f["receipt.json"], "--offline", "--refetch"}},
		{"missing root file", []string{"verify", f["receipt.json"], "--root", filepath.Join(f["dir"], "nope.json")}},
	}
	for _, c := range cases {
		if r := exec(t, "", c.args...); r.code != cli.ExitUsage {
			t.Errorf("%s: exit %d, want 64\n%s%s", c.name, r.code, r.stdout, r.stderr)
		}
	}
	// A file that reads but is not a receipt is exit 1 with first_failure schema, not 64.
	notReceipt := filepath.Join(f["dir"], "not.json")
	os.WriteFile(notReceipt, []byte(`{"hello":"world"}`), 0o644)
	r := exec(t, "", "verify", notReceipt, "--json")
	if r.code != 1 || !strings.Contains(r.stdout, `"check": "schema"`) {
		t.Errorf("not a receipt: exit %d\n%s", r.code, r.stdout)
	}
	if r := exec(t, "", "help"); r.code != 0 || !strings.HasPrefix(r.stdout, cli.Usage) {
		t.Errorf("help: %d %s", r.code, r.stdout)
	}
	if r := exec(t, "", "verify", "--help"); r.code != 0 || !strings.HasPrefix(r.stdout, cli.Usage) {
		t.Errorf("verify --help: %d %s", r.code, r.stdout)
	}
	// With --json a run that could not start still answers in JSON.
	r = exec(t, "", "verify", filepath.Join(f["dir"], "nope.json"), "--json")
	if r.code != cli.ExitUsage || !strings.Contains(r.stdout, `"exit": 64`) || !strings.Contains(r.stdout, `"error": "`) {
		t.Errorf("json usage error: %d %s", r.code, r.stdout)
	}
	if r := exec(t, "", "version"); r.code != 0 || !strings.HasPrefix(r.stdout, "recheck ") {
		t.Errorf("version: %d %s", r.code, r.stdout)
	}
}

func TestVerifyJSONAndStdin(t *testing.T) {
	f := fixtures(t)
	data, _ := os.ReadFile(f["receipt.json"])
	r := exec(t, string(data), "verify", "-", "--json", "--keys", f["keys.json"])
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	var rep struct {
		OK           bool              `json:"ok"`
		Exit         int               `json:"exit"`
		Checks       []map[string]any  `json:"checks"`
		Receipt      map[string]any    `json:"receipt"`
		FirstFailure map[string]string `json:"first_failure"`
		Refetch      []any             `json:"refetch"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("%v\n%s", err, r.stdout)
	}
	if !rep.OK || rep.Exit != 0 || len(rep.Checks) != 5 || rep.Receipt["id"] != "eb_2m4Kq8Xr7vTb3nHd" || rep.FirstFailure != nil || rep.Refetch == nil {
		t.Errorf("%+v", rep)
	}
	r = exec(t, "", "verify", f["tampered.json"], "--json")
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil || r.code != 1 || rep.FirstFailure["check"] != "self_hash" || rep.FirstFailure["detail"] == "" {
		t.Errorf("tampered json: %d %v %s", r.code, err, r.stdout)
	}
}

func TestRefetchAndFetchHash(t *testing.T) {
	f := fixtures(t)
	body := []byte("the source")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer srv.Close()
	r := exec(t, "", "fetch-hash", srv.URL+"/x")
	if r.code != 0 || !strings.Contains(r.stdout, "sha256    "+canonical.Sha256Hex(body)) || !strings.Contains(r.stdout, "status    200") {
		t.Errorf("fetch-hash: %d %s %s", r.code, r.stdout, r.stderr)
	}
	r = exec(t, "", "fetch-hash", srv.URL+"/x", "--json")
	if r.code != 0 || !strings.Contains(r.stdout, `"sha256": "`+canonical.Sha256Hex(body)+`"`) {
		t.Errorf("fetch-hash json: %s", r.stdout)
	}
	if r := exec(t, "", "fetch-hash", "https://exhibitb.autofract.com/api/receipt/x"); r.code != cli.ExitIncomplete || !strings.Contains(r.stderr, "issuer") {
		t.Errorf("issuer host: %d %s", r.code, r.stderr)
	}
	// --refetch against the vector: cdn.example.org does not resolve here, so the source is
	// unreachable and the run is incomplete, never failed.
	data, _ := os.ReadFile(f["receipt.json"])
	local := strings.Replace(string(data), "https://cdn.example.org/reports/2026/q1.pdf", srv.URL+"/q1.pdf", 1)
	// The URL is inside the hashed body, so the self_hash fails — but refetch still runs and
	// finds different bytes than the receipt recorded.
	localPath := filepath.Join(f["dir"], "local.json")
	os.WriteFile(localPath, []byte(local), 0o644)
	r = exec(t, "", "verify", localPath, "--refetch", "--json")
	if r.code != 1 || !strings.Contains(r.stdout, `"status": "changed"`) {
		t.Errorf("refetch: %d %s %s", r.code, r.stdout, r.stderr)
	}
}

func TestShowKeygenCountersign(t *testing.T) {
	f := fixtures(t)
	r := exec(t, "", "show", f["receipt.json"])
	if r.code != 0 || !strings.Contains(r.stdout, `"domain": "example.org"`) || strings.Contains(r.stdout, "final_url") {
		t.Errorf("show: %d %s", r.code, r.stdout)
	}
	shown := filepath.Join(f["dir"], "shown.json")
	os.WriteFile(shown, []byte(r.stdout), 0o644)
	// show prints the projection for reading; it cannot sign one, so the output has no
	// projection_sig and is not a verifiable artifact — verifying it is a schema failure that says so.
	if r := exec(t, "", "verify", shown, "--keys", f["keys.json"]); r.code != 1 || !strings.Contains(r.stdout, "projection_sig") {
		t.Errorf("verify shown projection: %d %s", r.code, r.stdout)
	}
	if r := exec(t, "", "show", f["keys.json"]); r.code != 1 {
		t.Errorf("show of a non-receipt: %d", r.code)
	}

	keyPath := filepath.Join(f["dir"], "counter.json")
	r = exec(t, "", "keygen", "--out", keyPath)
	if r.code != 0 || !strings.Contains(r.stderr, "wrote") {
		t.Fatalf("keygen: %d %s", r.code, r.stderr)
	}
	if r := exec(t, "", "keygen", "--out", keyPath); r.code != cli.ExitUsage {
		t.Errorf("keygen must not overwrite: %d", r.code)
	}
	r = exec(t, "", "keygen")
	if r.code != 0 || !strings.Contains(r.stdout, `"key_id": "eb-receipt-counter-`) || !strings.Contains(r.stdout, `"private_pkcs8_b64"`) {
		t.Errorf("keygen to stdout: %d %s", r.code, r.stdout)
	}

	signed := filepath.Join(f["dir"], "signed.json")
	r = exec(t, "", "countersign", f["receipt.json"], "--key", keyPath, "--out", signed)
	if r.code != 0 {
		t.Fatalf("countersign: %d %s", r.code, r.stderr)
	}
	out, _ := os.ReadFile(signed)
	if strings.Count(string(out), `"role":"counter"`) != 1 || !strings.HasPrefix(string(out), `{"binding":`) {
		t.Errorf("countersigned file: %s", out)
	}
	if r := exec(t, "", "verify", signed, "--keys", f["keys.json"]); r.code != 0 {
		t.Errorf("verify countersigned: %d %s", r.code, r.stdout)
	}
	// A counter-signature over a tampered receipt is refused; a projection too.
	if r := exec(t, "", "countersign", f["tampered.json"], "--key", keyPath); r.code != 1 {
		t.Errorf("countersign tampered: %d", r.code)
	}
	if r := exec(t, "", "countersign", f["projection.json"], "--key", keyPath); r.code != 1 {
		t.Errorf("countersign projection: %d", r.code)
	}
	if r := exec(t, "", "countersign", f["receipt.json"]); r.code != cli.ExitUsage {
		t.Errorf("countersign without a key: %d", r.code)
	}
	// The fixture key file (a different shape, same fields) also works as a signing key.
	if r := exec(t, "", "countersign", f["receipt.json"], "--key", f["test-key.json"]); r.code != 0 || !strings.Contains(r.stdout, `"key_id":"eb-receipt-test","role":"counter"`) {
		t.Errorf("countersign with the fixture key: %d %s", r.code, r.stderr)
	}
}

func TestBindCommand(t *testing.T) {
	f := fixtures(t)
	// A bundle for the vector receipt cannot be built without the original texts, so the
	// command's wiring is tested with a mismatching bundle and document: every check fails.
	bundle := filepath.Join(f["dir"], "binding.json")
	os.WriteFile(bundle, []byte(`{"binding_key":"`+strings.Repeat("00", 32)+`","claims":[{"n":1,"claim_text":"x","quote":null}]}`), 0o644)
	doc := filepath.Join(f["dir"], "doc.txt")
	os.WriteFile(doc, []byte("not the document"), 0o644)
	r := exec(t, "", "bind", f["receipt.json"], bundle, doc)
	if r.code != 1 || !strings.Contains(r.stdout, "- document_sha256") || !strings.Contains(r.stdout, "- binding_key") || !strings.Contains(r.stdout, "RESULT: FAIL") {
		t.Errorf("bind: %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	r = exec(t, "", "bind", f["receipt.json"], bundle, doc, "--json")
	if r.code != 1 || !strings.Contains(r.stdout, `"check": "document_sha256"`) {
		t.Errorf("bind json: %d %s", r.code, r.stdout)
	}
	if r := exec(t, "", "bind", f["receipt.json"], bundle); r.code != cli.ExitUsage {
		t.Errorf("bind arity: %d", r.code)
	}
	if r := exec(t, "", "bind", f["keys.json"], bundle, doc); r.code != 1 {
		t.Errorf("bind of a non-receipt: %d", r.code)
	}
	if r := exec(t, "", "bind", f["receipt.json"], doc, doc); r.code != cli.ExitUsage {
		t.Errorf("bind with a bad bundle: %d", r.code)
	}
}

func TestVectorsExtract(t *testing.T) {
	r := exec(t, "", "vectors-extract", filepath.Join("..", "spec", "vectors", "receipt.json"), "receipt")
	if r.code != 0 || !strings.HasPrefix(r.stdout, "{\n  \"v\": 1,") {
		t.Errorf("%d %s", r.code, r.stdout[:40])
	}
	// The lone-surrogate vector round-trips as the same escape.
	r = exec(t, "", "vectors-extract", filepath.Join("..", "spec", "vectors", "receipt.json"), "tampered")
	if r.code != 0 || !strings.Contains(r.stdout, `\ud83d`) {
		t.Errorf("surrogate escape lost: %d", r.code)
	}
}
