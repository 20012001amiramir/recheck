// Package cli is the recheck command line: every subcommand, its flags, its human and JSON output
// and its exit code. cmd/recheck wraps it for the native binary; cmd/wasm runs it under Node.
package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/20012001amiramir/recheck/bind"
	"github.com/20012001amiramir/recheck/canonical"
	"github.com/20012001amiramir/recheck/internal/build"
	"github.com/20012001amiramir/recheck/receipt"
	"github.com/20012001amiramir/recheck/refetch"
	"github.com/20012001amiramir/recheck/verify"
)

// IssuerURL is the only address this program ever contacts, and only for `verify <id>`.
const IssuerURL = "https://exhibitb.autofract.com"

// Exit codes (spec §12).
const (
	ExitOK         = 0
	ExitFail       = 1
	ExitIncomplete = 2
	ExitUsage      = 64
)

// Usage is what `recheck --help` prints.
const Usage = `recheck verify <receipt.json | receipt id> [--proof proof.json] [--root roots/DATE.json] [--keys keys.json] [--refetch] [--json] [--offline]
recheck bind <receipt.json> <binding.json> <document>
recheck fetch-hash <url>
recheck show <receipt.json>            (prints the public projection)
recheck keygen [--out key.json]        (ed25519 keypair for counter-signing)
recheck countersign <receipt.json> --key key.json [--out receipt.signed.json]
recheck version
`

const usageNotes = `
verify reads a file (or - for standard input) and never touches the network. Only a receipt id
in place of a file fetches that receipt's public projection from the issuer, and --offline
refuses even that. --refetch downloads each cited URL from this machine, never via the issuer; a
source that does not answer, or answers http 400 or worse, is reported unreachable, and a source
that changed or is unreachable is a warning, never a failure.
Exit codes: 0 every check passed, 1 a check failed, 2 nothing failed but something could not be
established (a warning), 64 usage. Add --json for machine output, --ascii for plain markers.
`

type env struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

// Main runs the command line and returns the exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	e := &env{stdin: stdin, stdout: stdout, stderr: stderr}
	refetch.UserAgent = "recheck/" + build.String() + " (+https://github.com/20012001amiramir/recheck)"
	if len(args) == 0 {
		fmt.Fprint(stderr, Usage)
		return ExitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "verify":
		return e.verify(rest)
	case "bind":
		return e.bind(rest)
	case "fetch-hash":
		return e.fetchHash(rest)
	case "show":
		return e.show(rest)
	case "keygen":
		return e.keygen(rest)
	case "countersign":
		return e.countersign(rest)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "recheck "+build.String())
		return ExitOK
	case "help", "--help", "-h":
		fmt.Fprint(stdout, Usage+usageNotes)
		return ExitOK
	case "vectors-extract":
		// Build helper: prints one member of a vector file as a standalone document.
		return e.vectorsExtract(rest)
	}
	return e.usage(fmt.Errorf("unknown command %q", cmd))
}

func (e *env) usage(err error) int {
	if errors.Is(err, errHelp) {
		fmt.Fprint(e.stdout, Usage+usageNotes)
		return ExitOK
	}
	fmt.Fprintln(e.stderr, "recheck: "+err.Error())
	fmt.Fprint(e.stderr, Usage)
	return ExitUsage
}

func (e *env) fail(code int, err error) int {
	fmt.Fprintln(e.stderr, "recheck: "+err.Error())
	return code
}

// ── arguments ─────────────────────────────────────────────────────────────

type parsedArgs struct {
	positional []string
	values     map[string]string
	bools      map[string]bool
}

// parseArgs accepts --flag, --flag value and --flag=value anywhere on the line.
func parseArgs(args []string, boolFlags, valueFlags []string) (*parsedArgs, error) {
	p := &parsedArgs{values: map[string]string{}, bools: map[string]bool{}}
	isBool := map[string]bool{}
	for _, f := range boolFlags {
		isBool[f] = true
	}
	isValue := map[string]bool{}
	for _, f := range valueFlags {
		isValue[f] = true
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-" || !strings.HasPrefix(a, "-") {
			p.positional = append(p.positional, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		value, hasValue := "", false
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name, value, hasValue = name[:eq], name[eq+1:], true
		}
		switch {
		case isBool[name]:
			if hasValue {
				return nil, fmt.Errorf("--%s takes no value", name)
			}
			p.bools[name] = true
		case isValue[name]:
			if !hasValue {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("--%s needs a value", name)
				}
				i++
				value = args[i]
			}
			p.values[name] = value
		case name == "help" || name == "h":
			return nil, errHelp
		default:
			return nil, fmt.Errorf("unknown flag %s", a)
		}
	}
	return p, nil
}

var errHelp = errors.New("help")

func readInput(e *env, path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(e.stdin)
	}
	return os.ReadFile(path)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ── verify ────────────────────────────────────────────────────────────────

func (e *env) verify(args []string) int {
	p, err := parseArgs(args, []string{"refetch", "json", "offline", "ascii"}, []string{"proof", "root", "keys"})
	if err != nil {
		return e.usage(err)
	}
	if len(p.positional) != 1 {
		return e.usage(errors.New("verify needs one receipt file or receipt id"))
	}
	if p.bools["offline"] && p.bools["refetch"] {
		return e.usage(errors.New("--offline and --refetch contradict each other"))
	}
	// With --json even a run that could not start answers in JSON, so a caller never has to
	// parse stderr.
	fail := func(code int, err error) int {
		if p.bools["json"] {
			e.stdout.Write(verify.Report{Exit: code, Error: err.Error()}.JSON())
			fmt.Fprintln(e.stdout)
			return code
		}
		return e.fail(code, err)
	}
	keys, err := loadKeys(p.values["keys"])
	if err != nil {
		return fail(ExitUsage, err)
	}

	target := p.positional[0]
	var input []byte
	switch {
	case target != "-" && receipt.ReceiptIDShape(target) && !fileExists(target):
		if p.bools["offline"] {
			return fail(ExitUsage, fmt.Errorf("--offline: %s is a receipt id, and fetching it means contacting the issuer", target))
		}
		fmt.Fprintln(e.stderr, "fetching from issuer (online)")
		var code int
		if input, code, err = fetchFromIssuer(target); err != nil {
			return fail(code, err)
		}
	default:
		if input, err = readInput(e, target); err != nil {
			return fail(ExitUsage, err)
		}
	}

	opts := verify.Options{Keys: keys}
	if path := p.values["root"]; path != "" {
		if opts.Root, err = os.ReadFile(path); err != nil {
			return fail(ExitUsage, err)
		}
	}
	if path := p.values["proof"]; path != "" {
		if opts.Proof, err = os.ReadFile(path); err != nil {
			return fail(ExitUsage, err)
		}
	}
	if p.bools["refetch"] {
		opts.Refetch = refetchHash
	}

	rep := verify.Run(input, opts)
	if p.bools["json"] {
		e.stdout.Write(rep.JSON())
		fmt.Fprintln(e.stdout)
	} else {
		e.printReport(rep, p.bools["ascii"])
	}
	return rep.Exit
}

func loadKeys(path string) (*receipt.KeySet, error) {
	keys, err := receipt.Pinned()
	if err != nil {
		return nil, fmt.Errorf("compiled-in keys: %w", err)
	}
	if path == "" {
		return keys, nil
	}
	extra, err := receipt.LoadKeySet(path)
	if err != nil {
		return nil, fmt.Errorf("--keys %s: %w", path, err)
	}
	if err := keys.Merge(extra); err != nil {
		return nil, fmt.Errorf("--keys %s: %w", path, err)
	}
	return keys, nil
}

func refetchHash(url string) (string, error) {
	r, err := refetch.Hash(url)
	if err != nil {
		return "", err
	}
	if r.Status >= 400 {
		return "", fmt.Errorf("http %d", r.Status)
	}
	return r.SHA256, nil
}

// issuerClient is the client of the one online path. A redirect off the issuer's hosts would
// carry the receipt id somewhere else and bring back a body from whoever answered it, which is
// what the checks would then run over; a redirect is followed only while it stays on the issuer
// over https, and only a few times.
func issuerClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= refetch.MaxRedirects {
				return fmt.Errorf("more than %d redirects", refetch.MaxRedirects)
			}
			if req.URL.Scheme != "https" || !refetch.IsIssuerHost(req.URL.Hostname()) {
				return fmt.Errorf("refusing a redirect off the issuer, to %s", req.URL.Redacted())
			}
			return nil
		},
	}
}

// fetchFromIssuer downloads a receipt's public projection: the one online path. With an error it
// returns the exit code for it — 64 when the issuer says it has no such receipt, since the id
// was the caller's; 2 for no answer or a broken one, since then no check could run.
func fetchFromIssuer(id string) ([]byte, int, error) {
	client := issuerClient()
	req, err := http.NewRequest(http.MethodGet, IssuerURL+"/api/receipt/"+id, nil)
	if err != nil {
		return nil, ExitUsage, err
	}
	req.Header.Set("User-Agent", refetch.UserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, ExitIncomplete, fmt.Errorf("fetching %s from the issuer: %w", id, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, ExitIncomplete, fmt.Errorf("reading %s from the issuer: %w", id, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return body, ExitOK, nil
	case http.StatusNotFound:
		return nil, ExitUsage, fmt.Errorf("the issuer has no receipt %s", id)
	default:
		return nil, ExitIncomplete, fmt.Errorf("the issuer answered http %d for %s", resp.StatusCode, id)
	}
}

func (e *env) marks(ascii bool) (map[string]string, string) {
	if ascii || !isTerminal(e.stdout) {
		return map[string]string{receipt.Pass: "+", receipt.Fail: "-", receipt.Warn: "!", receipt.Skip: "."}, " | "
	}
	return map[string]string{receipt.Pass: "✔", receipt.Fail: "✘", receipt.Warn: "!", receipt.Skip: "–"}, " · "
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func (e *env) printChecks(checks []receipt.Check, ascii bool) {
	marks, _ := e.marks(ascii)
	for _, c := range checks {
		fmt.Fprintf(e.stdout, "%s %-14s %s\n", marks[c.Status], c.Name, c.Detail)
	}
}

func result(exit int) string {
	switch exit {
	case ExitOK:
		return "PASS"
	case ExitFail:
		return "FAIL"
	case ExitIncomplete:
		return "INCOMPLETE"
	}
	return "ERROR"
}

func (e *env) printReport(rep verify.Report, ascii bool) {
	_, sep := e.marks(ascii)
	if rep.Error != "" {
		fmt.Fprintln(e.stdout, "ERROR: "+rep.Error)
		return
	}
	e.printChecks(rep.Checks, ascii)
	for _, item := range rep.Refetch {
		line := fmt.Sprintf("  %-11s claim %d %s", item.Status, item.N, item.URL)
		if item.Detail != "" {
			line += " (" + item.Detail + ")"
		}
		fmt.Fprintln(e.stdout, line)
	}
	if r := rep.Receipt; r != nil {
		seq := "unchained"
		if r.Seq != nil {
			seq = "seq " + strconv.FormatInt(*r.Seq, 10)
		}
		fmt.Fprintln(e.stdout, strings.Join([]string{"receipt " + r.ID, seq, "issued " + r.IssuedAt, "key " + r.KeyID}, sep))
	}
	fmt.Fprintln(e.stdout, "RESULT: "+result(rep.Exit))
}

// ── bind ──────────────────────────────────────────────────────────────────

type bindReport struct {
	OK           bool            `json:"ok"`
	Exit         int             `json:"exit"`
	Checks       []receipt.Check `json:"checks"`
	Receipt      *verify.Info    `json:"receipt"`
	FirstFailure *verify.Failure `json:"first_failure"`
}

func (e *env) bind(args []string) int {
	p, err := parseArgs(args, []string{"json", "ascii"}, nil)
	if err != nil {
		return e.usage(err)
	}
	if len(p.positional) != 3 {
		return e.usage(errors.New("bind needs <receipt.json> <binding.json> <document>"))
	}
	receiptData, err := os.ReadFile(p.positional[0])
	if err != nil {
		return e.fail(ExitUsage, err)
	}
	rec, _, err := receipt.Parse(receiptData)
	if err != nil {
		return e.fail(ExitFail, fmt.Errorf("%s is not a receipt: %v", p.positional[0], err))
	}
	bundleData, err := os.ReadFile(p.positional[1])
	if err != nil {
		return e.fail(ExitUsage, err)
	}
	bundle, err := bind.ParseBundle(bundleData)
	if err != nil {
		return e.fail(ExitUsage, err)
	}
	document, err := os.ReadFile(p.positional[2])
	if err != nil {
		return e.fail(ExitUsage, err)
	}

	checks := bind.Check(rec, bundle, document)
	rep := bindReport{Checks: checks, Exit: receipt.ExitCode(checks), Receipt: &verify.Info{ID: rec.ID, Seq: rec.Seq, IssuedAt: rec.IssuedAt, KeyID: rec.Issuer.KeyID, Kind: rec.Kind}}
	if f := receipt.FirstFailure(checks); f != nil {
		rep.FirstFailure = &verify.Failure{Check: f.Name, Detail: f.Detail}
	}
	rep.OK = rep.FirstFailure == nil
	if p.bools["json"] {
		out, _ := json.MarshalIndent(rep, "", "  ")
		e.stdout.Write(out)
		fmt.Fprintln(e.stdout)
		return rep.Exit
	}
	e.printChecks(checks, p.bools["ascii"])
	fmt.Fprintln(e.stdout, "RESULT: "+result(rep.Exit))
	return rep.Exit
}

// ── fetch-hash ────────────────────────────────────────────────────────────

func (e *env) fetchHash(args []string) int {
	p, err := parseArgs(args, []string{"json"}, nil)
	if err != nil {
		return e.usage(err)
	}
	if len(p.positional) != 1 {
		return e.usage(errors.New("fetch-hash needs one URL"))
	}
	res, err := refetch.Hash(p.positional[0])
	if err != nil {
		return e.fail(ExitIncomplete, err)
	}
	if p.bools["json"] {
		out, _ := json.MarshalIndent(res, "", "  ")
		e.stdout.Write(out)
		fmt.Fprintln(e.stdout)
		return ExitOK
	}
	fmt.Fprintf(e.stdout, "sha256    %s\nbytes     %d\nstatus    %d\nfinal_url %s\n", res.SHA256, res.Bytes, res.Status, res.FinalURL)
	return ExitOK
}

// ── show ──────────────────────────────────────────────────────────────────

func (e *env) show(args []string) int {
	p, err := parseArgs(args, nil, nil)
	if err != nil {
		return e.usage(err)
	}
	if len(p.positional) != 1 {
		return e.usage(errors.New("show needs one receipt file"))
	}
	data, err := readInput(e, p.positional[0])
	if err != nil {
		return e.fail(ExitUsage, err)
	}
	rec, raw, err := receipt.Parse(data)
	if err != nil {
		return e.fail(ExitFail, fmt.Errorf("not a receipt: %v", err))
	}
	proj, err := receipt.Project(rec, raw)
	if err != nil {
		return e.fail(ExitFail, err)
	}
	out, err := canonical.Pretty(proj)
	if err != nil {
		return e.fail(ExitFail, err)
	}
	e.stdout.Write(out)
	return ExitOK
}

// ── keygen / countersign ──────────────────────────────────────────────────

// PKCS#8 PrivateKeyInfo for an Ed25519 key is a fixed 16-byte prefix followed by the 32-byte seed.
var pkcs8Prefix = []byte{0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20}

type keyFile struct {
	KeyID        string `json:"key_id"`
	Alg          string `json:"alg"`
	PublicKey    string `json:"public_key"`
	PrivatePKCS8 string `json:"private_pkcs8_b64"`
	CreatedAt    string `json:"created_at"`
	Note         string `json:"note"`
}

func newKeyID() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	out := make([]byte, len(buf))
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	// The receipt schema admits only eb-receipt-<name> as a key id, counter-signers included.
	return "eb-receipt-counter-" + string(out), nil
}

func (e *env) keygen(args []string) int {
	p, err := parseArgs(args, nil, []string{"out"})
	if err != nil {
		return e.usage(err)
	}
	if len(p.positional) != 0 {
		return e.usage(errors.New("keygen takes no positional arguments"))
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return e.fail(ExitUsage, err)
	}
	id, err := newKeyID()
	if err != nil {
		return e.fail(ExitUsage, err)
	}
	k := keyFile{
		KeyID:        id,
		Alg:          "ed25519",
		PublicKey:    receipt.EncodeKey(pub),
		PrivatePKCS8: base64.StdEncoding.EncodeToString(append(append([]byte{}, pkcs8Prefix...), priv.Seed()...)),
		CreatedAt:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Note:         "private_pkcs8_b64 is the secret half: keep it to yourself; share key_id and public_key with anyone who should check your counter-signature.",
	}
	out, _ := json.MarshalIndent(k, "", "  ")
	out = append(out, '\n')
	if path := p.values["out"]; path != "" {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return e.fail(ExitUsage, fmt.Errorf("refusing to overwrite: %w", err))
		}
		defer f.Close()
		if _, err := f.Write(out); err != nil {
			return e.fail(ExitUsage, err)
		}
		fmt.Fprintf(e.stderr, "wrote %s (key id %s)\n", path, id)
		return ExitOK
	}
	e.stdout.Write(out)
	return ExitOK
}

func loadPrivateKey(path string) (string, ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	raw, err := canonical.Parse(data)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %v", path, err)
	}
	id := raw.Get("key_id")
	pk := raw.Get("private_pkcs8_b64")
	if id == nil || id.Kind != canonical.String || !receipt.KeyIDShape(id.Str) || pk == nil || pk.Kind != canonical.String {
		return "", nil, fmt.Errorf("%s: expected {key_id, private_pkcs8_b64, public_key} as written by recheck keygen", path)
	}
	der, err := base64.StdEncoding.DecodeString(pk.Str)
	if err != nil {
		return "", nil, fmt.Errorf("%s: private_pkcs8_b64: %v", path, err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %v", path, err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return "", nil, fmt.Errorf("%s: not an ed25519 key", path)
	}
	if pub := raw.Get("public_key"); pub != nil && pub.Kind == canonical.String && pub.Str != receipt.EncodeKey(priv.Public().(ed25519.PublicKey)) {
		return "", nil, fmt.Errorf("%s: public_key does not match the private key", path)
	}
	return id.Str, priv, nil
}

func (e *env) countersign(args []string) int {
	p, err := parseArgs(args, nil, []string{"key", "out"})
	if err != nil {
		return e.usage(err)
	}
	if len(p.positional) != 1 || p.values["key"] == "" {
		return e.usage(errors.New("countersign needs <receipt.json> --key key.json"))
	}
	keyID, priv, err := loadPrivateKey(p.values["key"])
	if err != nil {
		return e.fail(ExitUsage, err)
	}
	data, err := readInput(e, p.positional[0])
	if err != nil {
		return e.fail(ExitUsage, err)
	}
	rec, raw, err := receipt.Parse(data)
	if err != nil {
		return e.fail(ExitFail, fmt.Errorf("not a receipt: %v", err))
	}
	if rec.Projected {
		return e.fail(ExitFail, errors.New("refusing to counter-sign a public projection: the sealed body is not present"))
	}
	computed, err := canonical.SelfHash(raw)
	if err != nil || computed != rec.SelfHash {
		return e.fail(ExitFail, errors.New("refusing to counter-sign: the receipt does not hash to its self_hash"))
	}
	if len(rec.Signatures) >= receipt.MaxSignatures {
		return e.fail(ExitFail, fmt.Errorf("the receipt already carries %d signatures, the most a receipt may hold", receipt.MaxSignatures))
	}
	sig, err := receipt.Sign(priv, rec.SelfHash)
	if err != nil {
		return e.fail(ExitFail, err)
	}
	entry := &canonical.Value{Kind: canonical.Object, Members: []canonical.Member{
		{Key: "key_id", Value: &canonical.Value{Kind: canonical.String, Str: keyID}},
		{Key: "alg", Value: &canonical.Value{Kind: canonical.String, Str: "ed25519"}},
		{Key: "sig", Value: &canonical.Value{Kind: canonical.String, Str: sig}},
		{Key: "role", Value: &canonical.Value{Kind: canonical.String, Str: receipt.RoleCounter}},
	}}
	for i := range raw.Members {
		if raw.Members[i].Key == "signatures" {
			sigs := *raw.Members[i].Value
			sigs.Array = append(append([]*canonical.Value{}, sigs.Array...), entry)
			raw.Members[i].Value = &sigs
		}
	}
	out, err := canonical.Canonicalize(raw)
	if err != nil {
		return e.fail(ExitFail, err)
	}
	if path := p.values["out"]; path != "" {
		if err := os.WriteFile(path, out, 0o644); err != nil {
			return e.fail(ExitUsage, err)
		}
		fmt.Fprintf(e.stderr, "wrote %s: receipt %s counter-signed by %s\n", path, rec.ID, keyID)
		return ExitOK
	}
	e.stdout.Write(out)
	fmt.Fprintln(e.stdout)
	return ExitOK
}

// ── build helper ──────────────────────────────────────────────────────────

func (e *env) vectorsExtract(args []string) int {
	if len(args) != 2 {
		return e.usage(errors.New("vectors-extract <vector.json> <member>"))
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return e.fail(ExitUsage, err)
	}
	raw, err := canonical.ParseLenient(data)
	if err != nil {
		return e.fail(ExitUsage, err)
	}
	member := raw.Get(args[1])
	if member == nil {
		return e.fail(ExitUsage, fmt.Errorf("no member %q", args[1]))
	}
	out, err := canonical.Pretty(member)
	if err != nil {
		return e.fail(ExitUsage, err)
	}
	e.stdout.Write(out)
	return ExitOK
}
