package receipt

import (
	"bytes"
	"errors"
	"strconv"
	"strings"

	"github.com/20012001amiramir/recheck/canonical"
)

// Check statuses (§12).
const (
	Pass = "pass"
	Fail = "fail"
	Warn = "warn"
	Skip = "skip"
)

// Check is one named verifier check with its status and a one-line detail for people.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// The five receipt checks, in order (§12).
var CheckNames = []string{"schema", "self_hash", "signature", "key_pinned", "chain_fields"}

// The five checks a projection runs: checks 2 and 3 are taken over the projection itself (§11, §12).
var ProjectionCheckNames = []string{"schema", "projection_self_hash", "projection_signature", "key_pinned", "chain_fields"}

// ProjectionSelfHash is sha256 of the canonical bytes of a projection with only its top-level
// projection_sig removed (§11) — what projection_sig signs.
func ProjectionSelfHash(raw *canonical.Value) (string, error) {
	if raw == nil || raw.Kind != canonical.Object {
		return "", errors.New("a projection self-hash needs an object")
	}
	out := &canonical.Value{Kind: canonical.Object}
	for _, m := range raw.Members {
		if m.Key == "projection_sig" {
			continue
		}
		out.Members = append(out.Members, m)
	}
	b, err := canonical.Canonicalize(out)
	if err != nil {
		return "", err
	}
	return canonical.Sha256Hex(b), nil
}

// Result is the outcome of the five receipt checks.
type Result struct {
	Checks []Check
	// Receipt is nil when the schema check failed.
	Receipt *Receipt
	// Raw is the parsed JSON, nil when the input was not JSON.
	Raw *canonical.Value
	// Err is the parse or schema error behind a schema failure.
	Err error
}

// OK is true when no check failed; a warn never makes it false.
func (r Result) OK() bool { return FirstFailure(r.Checks) == nil }

// FirstFailure is the first check whose status is fail, or nil.
func FirstFailure(checks []Check) *Check {
	for i := range checks {
		if checks[i].Status == Fail {
			return &checks[i]
		}
	}
	return nil
}

// ExitCode maps checks to the exit codes of §12: 0 when every check passed or was skipped, 1 on
// any failure, 2 when nothing failed but something could not be established (a warn).
func ExitCode(checks []Check) int {
	code := 0
	for _, c := range checks {
		switch c.Status {
		case Fail:
			return 1
		case Warn:
			code = 2
		}
	}
	return code
}

// Verify runs the five checks of §12 on one JSON document — a receipt or a projection — against a
// pinned key set. A nil or empty key set makes key_pinned skip.
//
// Check 1 never stops checks 2–5. The cryptography is read straight off the parsed document, so a
// reader is told whether the bytes in front of them are the bytes the issuer signed even when this
// verifier could not read every field — which is the difference between "this tool is older than
// this record" and "this record is not what it says it is" (§12, §15.1).
func Verify(data []byte, keys *KeySet) Result {
	r, raw, err := Parse(data)
	res := Result{Receipt: r, Raw: raw, Err: err}
	if err != nil {
		detail := err.Error()
		if ce, notJSON := err.(*canonical.Error); notJSON {
			detail = ce.Path + ": " + ce.Msg
		}
		res.Checks = append(res.Checks, Check{"schema", Fail, detail})
	} else {
		res.Checks = append(res.Checks, schemaCheck(r))
	}
	res.Checks = append(res.Checks, cryptoChecks(r, raw, keys)...)
	return res
}

// VerifyParsed runs checks 1–5 on an already validated receipt and its parsed JSON.
func VerifyParsed(r *Receipt, raw *canonical.Value, keys *KeySet) Result {
	res := Result{Receipt: r, Raw: raw}
	res.Checks = append(res.Checks, schemaCheck(r))
	res.Checks = append(res.Checks, cryptoChecks(r, raw, keys)...)
	return res
}

// maxNamedWarnings caps how many unknown-member paths one detail line spells out. The count in
// front of them is always exact, so a reader is never told fewer were found than there were.
const maxNamedWarnings = 8

// schemaCheck is check 1 for a document that matched a schema: pass, or warn when it carried
// members no shape in the spec names (§15.1).
func schemaCheck(r *Receipt) Check {
	what := "receipt v1, kind " + r.Kind
	if r.Projected {
		what = "public projection of receipt v1, kind " + r.Kind
	}
	if len(r.SchemaWarnings) == 0 {
		return Check{"schema", Pass, what}
	}
	paths := make([]string, 0, maxNamedWarnings+1)
	for i, w := range r.SchemaWarnings {
		if i == maxNamedWarnings {
			paths = append(paths, "…")
			break
		}
		paths = append(paths, w.Path)
	}
	noun := " members"
	if len(r.SchemaWarnings) == 1 {
		noun = " member"
	}
	return Check{"schema", Warn, what + "; " + strconv.Itoa(len(r.SchemaWarnings)) + noun +
		" this verifier does not know: " + strings.Join(paths, ", ") +
		" — this tool is older than this record; the checks below still say whether it was signed"}
}

// signedDoc is what checks 2–5 are taken over. It comes from the validated receipt when there is
// one and is read best-effort off the parsed JSON when check 1 refused the document, so the
// cryptography is reported either way (§12).
type signedDoc struct {
	// object is false when there is nothing to check at all: the input was not JSON, or its
	// top-level value was not an object.
	object    bool
	projected bool
	selfHash  string
	publicKey string
	keyID     string
	kind      string
	seq       *int64
	prevHash  *string
	sigs      []Signature
	projSig   string
}

func rawStr(v *canonical.Value) string {
	if v != nil && v.Kind == canonical.String {
		return v.Str
	}
	return ""
}

func docOf(r *Receipt, raw *canonical.Value) signedDoc {
	if r != nil {
		return signedDoc{
			object: true, projected: r.Projected, selfHash: r.SelfHash, publicKey: r.Issuer.PublicKey,
			keyID: r.Issuer.KeyID, kind: r.Kind, seq: r.Seq, prevHash: r.PrevHash,
			sigs: r.Signatures, projSig: r.ProjectionSig,
		}
	}
	if raw == nil || raw.Kind != canonical.Object {
		return signedDoc{}
	}
	// A document that failed check 1 still names, or fails to name, the few things checks 2–5 are
	// taken over. Nothing read here is trusted for meaning: a member of the wrong type reads as
	// absent, and the check then says what it could not establish rather than guessing.
	d := signedDoc{
		object:    true,
		projected: raw.Get("projection_sig") != nil,
		selfHash:  rawStr(raw.Get("self_hash")),
		kind:      rawStr(raw.Get("kind")),
		projSig:   rawStr(raw.Get("projection_sig")),
	}
	if iss := raw.Get("issuer"); iss != nil && iss.Kind == canonical.Object {
		d.publicKey, d.keyID = rawStr(iss.Get("public_key")), rawStr(iss.Get("key_id"))
	}
	if seq := raw.Get("seq"); seq != nil && seq.Kind == canonical.Number && seq.IsInt {
		n := seq.Int
		d.seq = &n
	}
	if prev := raw.Get("prev_hash"); prev != nil && prev.Kind == canonical.String {
		p := prev.Str
		d.prevHash = &p
	}
	if sigs := raw.Get("signatures"); sigs != nil && sigs.Kind == canonical.Array {
		for _, sv := range sigs.Array {
			if sv.Kind != canonical.Object {
				continue
			}
			d.sigs = append(d.sigs, Signature{
				KeyID: rawStr(sv.Get("key_id")), Alg: rawStr(sv.Get("alg")),
				Sig: rawStr(sv.Get("sig")), Role: rawStr(sv.Get("role")),
			})
		}
	}
	return d
}

func issuerSignaturesOf(sigs []Signature) []Signature {
	var out []Signature
	for _, s := range sigs {
		if s.Role == RoleIssuer {
			out = append(out, s)
		}
	}
	return out
}

// cryptoChecks is checks 2–5: the hash, the signature, the pin and the chain position. They run
// whenever there is a JSON object to run them on, whatever check 1 made of it.
func cryptoChecks(r *Receipt, raw *canonical.Value, keys *KeySet) []Check {
	var out []Check
	add := func(name, status, detail string) { out = append(out, Check{name, status, detail}) }

	d := docOf(r, raw)
	if !d.object {
		for _, name := range CheckNames[1:] {
			add(name, Skip, "the input is not a JSON object")
		}
		return out
	}

	pub, pubErr := DecodeKey(d.publicKey)

	if d.projected {
		// Checks 2 and 3 for a projection are its own hash and signature (§11): the projection
		// self-hash over every member but projection_sig, and projection_sig verified over it. So a
		// genuine projection passes outright, and any altered field fails projection_signature.
		hash, err := ProjectionSelfHash(raw)
		switch {
		case err != nil:
			add("projection_self_hash", Fail, "could not canonicalize: "+err.Error())
			add("projection_signature", Skip, "the projection self-hash could not be computed")
		default:
			add("projection_self_hash", Pass, hash)
			switch {
			case pubErr != nil:
				add("projection_signature", Fail, "issuer public key: "+pubErr.Error())
			case VerifyRaw(pub, hash, d.projSig):
				add("projection_signature", Pass, "ed25519 by "+d.keyID)
			default:
				add("projection_signature", Fail, "projection_sig does not verify over the projection self-hash")
			}
		}
	} else {
		computed, err := canonical.SelfHash(raw)
		switch {
		case err != nil:
			add("self_hash", Fail, "could not canonicalize: "+err.Error())
		case d.selfHash == "":
			add("self_hash", Fail, "computed "+computed+", the document carries no self_hash to compare it against")
		case computed == d.selfHash:
			add("self_hash", Pass, d.selfHash)
		default:
			add("self_hash", Fail, "computed "+computed+", receipt says "+d.selfHash)
		}

		issuerSigs := issuerSignaturesOf(d.sigs)
		switch {
		case len(issuerSigs) == 0:
			add("signature", Fail, "no issuer signature")
		case len(issuerSigs) > 1:
			add("signature", Fail, strconv.Itoa(len(issuerSigs))+" issuer signatures, expected exactly one")
		case issuerSigs[0].KeyID != d.keyID:
			add("signature", Fail, "signature key_id "+issuerSigs[0].KeyID+" is not the issuer's "+d.keyID)
		case pubErr != nil:
			add("signature", Fail, "issuer public key: "+pubErr.Error())
		case d.selfHash == "":
			add("signature", Fail, "the document carries no self_hash for a signature to be taken over")
		case VerifyRaw(pub, d.selfHash, issuerSigs[0].Sig):
			add("signature", Pass, "ed25519 by "+issuerSigs[0].KeyID)
		default:
			add("signature", Fail, "ed25519 signature by "+issuerSigs[0].KeyID+" does not verify over self_hash")
		}
	}

	switch pinned, ok := keys.Lookup(PurposeReceipt, d.keyID); {
	case keys.Len() == 0:
		add("key_pinned", Skip, "the key set handed to this check is empty — verified against the key inside the receipt only")
	case d.keyID == "":
		add("key_pinned", Skip, "the document names no issuer key_id to look up")
	case !ok:
		add("key_pinned", Warn, "issuer key not pinned — verified against the key inside the receipt only ("+d.keyID+")")
	case pinned.Broken:
		add("key_pinned", Fail, "the pinned entry for "+d.keyID+" is not canonical base64 of 32 bytes: the pin itself is broken")
	case pubErr == nil && bytes.Equal(pinned.PublicKey, pub):
		add("key_pinned", Pass, d.keyID)
	default:
		add("key_pinned", Fail, d.keyID+" is pinned to a different public key")
	}

	switch d.kind {
	case KindUnchained:
		if d.seq == nil && d.prevHash == nil {
			add("chain_fields", Skip, "unchained receipt: not anchored to the public chain")
		} else {
			add("chain_fields", Fail, "an unchained receipt must have seq and prev_hash null")
		}
	case KindChained:
		if d.seq != nil && *d.seq >= 1 && d.prevHash != nil && Hex64Shape(*d.prevHash) {
			add("chain_fields", Pass, "seq "+strconv.FormatInt(*d.seq, 10))
		} else {
			add("chain_fields", Fail, "a chained receipt needs seq >= 1 and a hex prev_hash")
		}
	default:
		add("chain_fields", Skip, "the document names neither receipt kind")
	}
	return out
}
