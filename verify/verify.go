// Package verify composes the checks of spec §12 into one report: the five receipt checks, the
// root-file and inclusion checks when a root file and proof are supplied, and the optional
// refetch of every cited URL. It is what the CLI prints and what the browser API returns.
package verify

import (
	"encoding/json"
	"strconv"

	"github.com/20012001amiramir/recheck/canonical"
	"github.com/20012001amiramir/recheck/receipt"
	"github.com/20012001amiramir/recheck/root"
)

// Options select the optional checks.
type Options struct {
	// Keys is the pinned key set; nil or empty makes key_pinned skip.
	Keys *receipt.KeySet
	// Root and Proof are the root file and the proof (§9, §10) as JSON; both are needed for the
	// inclusion check, and giving one without the other is reported as a warning.
	Root  []byte
	Proof []byte
	// Refetch, when set, is called for every claim whose exists.final_url and content_sha256 are
	// present and must return the sha256 of the bytes it downloaded. It is never called for a
	// projection, which carries no URLs.
	Refetch func(url string) (sha256 string, err error)
}

// Info is the receipt line of the report.
type Info struct {
	ID       string `json:"id"`
	Seq      *int64 `json:"seq"`
	IssuedAt string `json:"issued_at"`
	KeyID    string `json:"key_id"`
	Kind     string `json:"kind"`
}

// Failure is the first failing check.
type Failure struct {
	Check  string `json:"check"`
	Detail string `json:"detail"`
}

// RefetchItem is one refetched claim: match, changed or unreachable.
type RefetchItem struct {
	N      int64  `json:"n"`
	Status string `json:"status"`
	URL    string `json:"url"`
	Detail string `json:"detail,omitempty"`
}

// Report is the machine-readable result (the --json output).
type Report struct {
	OK           bool            `json:"ok"`
	Exit         int             `json:"exit"`
	Checks       []receipt.Check `json:"checks"`
	Receipt      *Info           `json:"receipt"`
	FirstFailure *Failure        `json:"first_failure"`
	Refetch      []RefetchItem   `json:"refetch"`
	// Error is set, with Exit 64, when the verifier could not run at all — a key set that does
	// not parse, for instance — rather than when a check failed.
	Error string `json:"error,omitempty"`
}

// Usage is a report for a run that could not start.
func Usage(msg string) Report {
	return Report{Exit: 64, Checks: []receipt.Check{}, Refetch: []RefetchItem{}, Error: msg}
}

// JSON renders the report.
func (r Report) JSON() []byte {
	if r.Checks == nil {
		r.Checks = []receipt.Check{}
	}
	if r.Refetch == nil {
		r.Refetch = []RefetchItem{}
	}
	out, _ := json.MarshalIndent(r, "", "  ")
	return out
}

// Run verifies one JSON document — a receipt or a projection.
func Run(input []byte, opts Options) Report {
	res := receipt.Verify(input, opts.Keys)
	rep := Report{Checks: res.Checks, Refetch: []RefetchItem{}, Receipt: info(res)}

	if opts.Root != nil || opts.Proof != nil {
		rep.Checks = append(rep.Checks, rootChecks(res, opts)...)
	}
	if opts.Refetch != nil {
		check, items := refetchAll(res.Receipt, opts.Refetch)
		rep.Checks = append(rep.Checks, check)
		rep.Refetch = items
	}

	rep.Exit = receipt.ExitCode(rep.Checks)
	if f := receipt.FirstFailure(rep.Checks); f != nil {
		rep.FirstFailure = &Failure{Check: f.Name, Detail: f.Detail}
	}
	rep.OK = rep.FirstFailure == nil
	return rep
}

func info(res receipt.Result) *Info {
	if res.Receipt != nil {
		r := res.Receipt
		return &Info{ID: r.ID, Seq: r.Seq, IssuedAt: r.IssuedAt, KeyID: r.Issuer.KeyID, Kind: r.Kind}
	}
	// Best effort from a document that failed its schema, so a reader still sees which receipt
	// they were looking at.
	raw := res.Raw
	if raw == nil || raw.Kind != canonical.Object {
		return nil
	}
	str := func(v *canonical.Value) string {
		if v != nil && v.Kind == canonical.String {
			return v.Str
		}
		return ""
	}
	out := &Info{ID: str(raw.Get("id")), IssuedAt: str(raw.Get("issued_at")), Kind: str(raw.Get("kind"))}
	if seq := raw.Get("seq"); seq != nil && seq.Kind == canonical.Number && seq.IsInt {
		n := seq.Int
		out.Seq = &n
	}
	if iss := raw.Get("issuer"); iss != nil {
		out.KeyID = str(iss.Get("key_id"))
	}
	return out
}

func rootChecks(res receipt.Result, opts Options) []receipt.Check {
	var checks []receipt.Check
	var file *root.File
	if opts.Root != nil {
		var rc []receipt.Check
		file, rc = root.Verify(opts.Root, opts.Keys)
		checks = append(checks, rc...)
	}
	switch {
	case opts.Proof == nil:
		checks = append(checks, receipt.Check{Name: "inclusion", Status: receipt.Warn, Detail: "a root file was given without a proof: pass --proof <proof.json> to check inclusion"})
	case opts.Root == nil:
		checks = append(checks, receipt.Check{Name: "inclusion", Status: receipt.Warn, Detail: "a proof was given without its root file: pass --root roots/<date>.json to check inclusion"})
	default:
		id, selfHash := "", ""
		if res.Receipt != nil {
			id, selfHash = res.Receipt.ID, res.Receipt.SelfHash
		}
		checks = append(checks, root.Inclusion(opts.Proof, file, id, selfHash))
	}
	return checks
}

// Refetch statuses.
const (
	Match       = "match"
	Changed     = "changed"
	Unreachable = "unreachable"
)

func refetchAll(r *receipt.Receipt, fetch func(string) (string, error)) (receipt.Check, []RefetchItem) {
	items := []RefetchItem{}
	check := func(status, detail string) receipt.Check {
		return receipt.Check{Name: "refetch", Status: status, Detail: detail}
	}
	if r == nil {
		return check(receipt.Skip, "schema failed"), items
	}
	if r.Projected {
		return check(receipt.Skip, "a public projection carries no URLs to refetch"), items
	}
	skipped := 0
	counts := map[string]int{}
	for _, c := range r.Claims {
		if c.Exists.FinalURL == nil || c.Exists.ContentSHA256 == nil {
			if c.Exists.FinalURL != nil {
				skipped++
			}
			continue
		}
		item := RefetchItem{N: c.N, URL: *c.Exists.FinalURL}
		got, err := fetch(item.URL)
		switch {
		case err != nil:
			item.Status = Unreachable
			item.Detail = err.Error()
		case got == *c.Exists.ContentSHA256:
			item.Status = Match
		default:
			item.Status = Changed
			item.Detail = "now " + got + ", receipt says " + *c.Exists.ContentSHA256
		}
		counts[item.Status]++
		items = append(items, item)
	}
	total := len(items)
	if total == 0 {
		return check(receipt.Skip, "no claim carries a URL with a content hash to refetch"), items
	}
	detail := strconv.Itoa(counts[Match]) + " of " + strconv.Itoa(total) + " sources still carry the bytes the receipt recorded"
	if counts[Changed] > 0 {
		detail += "; " + strconv.Itoa(counts[Changed]) + " changed since issue"
	}
	if counts[Unreachable] > 0 {
		detail += "; " + strconv.Itoa(counts[Unreachable]) + " unreachable from here"
	}
	if skipped > 0 {
		detail += "; " + strconv.Itoa(skipped) + " without a recorded content hash not fetched"
	}
	if counts[Changed] > 0 || counts[Unreachable] > 0 {
		// A changed source does not make the receipt wrong — it attests the bytes at issue time —
		// but the reader could not confirm the source still says the same, hence a warning.
		return check(receipt.Warn, detail), items
	}
	return check(receipt.Pass, detail), items
}
