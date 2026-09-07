package receipt

import (
	"bytes"
	"errors"
	"strconv"

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
func Verify(data []byte, keys *KeySet) Result {
	r, raw, err := Parse(data)
	if err != nil {
		res := Result{Raw: raw, Err: err}
		detail := err.Error()
		if ce, notJSON := err.(*canonical.Error); notJSON {
			detail = ce.Path + ": " + ce.Msg
		}
		res.Checks = append(res.Checks, Check{"schema", Fail, detail})
		for _, name := range CheckNames[1:] {
			res.Checks = append(res.Checks, Check{name, Skip, "schema failed"})
		}
		return res
	}
	res := VerifyParsed(r, raw, keys)
	res.Raw = raw
	return res
}

// VerifyParsed runs checks 1–5 on an already validated receipt and its parsed JSON.
func VerifyParsed(r *Receipt, raw *canonical.Value, keys *KeySet) Result {
	res := Result{Receipt: r, Raw: raw}
	add := func(name, status, detail string) { res.Checks = append(res.Checks, Check{name, status, detail}) }

	if r.Projected {
		add("schema", Pass, "public projection of receipt v1, kind "+r.Kind)
	} else {
		add("schema", Pass, "receipt v1, kind "+r.Kind)
	}

	pub, pubErr := DecodeKey(r.Issuer.PublicKey)

	if r.Projected {
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
			case VerifyRaw(pub, hash, r.ProjectionSig):
				add("projection_signature", Pass, "ed25519 by "+r.Issuer.KeyID)
			default:
				add("projection_signature", Fail, "projection_sig does not verify over the projection self-hash")
			}
		}
	} else {
		computed, err := canonical.SelfHash(raw)
		switch {
		case err != nil:
			add("self_hash", Fail, "could not canonicalize: "+err.Error())
		case computed == r.SelfHash:
			add("self_hash", Pass, r.SelfHash)
		default:
			add("self_hash", Fail, "computed "+computed+", receipt says "+r.SelfHash)
		}

		issuerSigs := r.IssuerSignatures()
		switch {
		case len(issuerSigs) == 0:
			add("signature", Fail, "no issuer signature")
		case len(issuerSigs) > 1:
			add("signature", Fail, strconv.Itoa(len(issuerSigs))+" issuer signatures, expected exactly one")
		case issuerSigs[0].KeyID != r.Issuer.KeyID:
			add("signature", Fail, "signature key_id "+issuerSigs[0].KeyID+" is not the issuer's "+r.Issuer.KeyID)
		case pubErr != nil:
			add("signature", Fail, "issuer public key: "+pubErr.Error())
		case VerifyRaw(pub, r.SelfHash, issuerSigs[0].Sig):
			add("signature", Pass, "ed25519 by "+issuerSigs[0].KeyID)
		default:
			add("signature", Fail, "ed25519 signature by "+issuerSigs[0].KeyID+" does not verify over self_hash")
		}
	}

	switch pinned, ok := keys.Lookup(PurposeReceipt, r.Issuer.KeyID); {
	case keys.Len() == 0:
		add("key_pinned", Skip, "the key set handed to this check is empty — verified against the key inside the receipt only")
	case !ok:
		add("key_pinned", Warn, "issuer key not pinned — verified against the key inside the receipt only ("+r.Issuer.KeyID+")")
	case pinned.Broken:
		add("key_pinned", Fail, "the pinned entry for "+r.Issuer.KeyID+" is not canonical base64 of 32 bytes: the pin itself is broken")
	case pubErr == nil && bytes.Equal(pinned.PublicKey, pub):
		add("key_pinned", Pass, r.Issuer.KeyID)
	default:
		add("key_pinned", Fail, r.Issuer.KeyID+" is pinned to a different public key")
	}

	if r.Kind == KindUnchained {
		if r.Seq == nil && r.PrevHash == nil {
			add("chain_fields", Skip, "unchained receipt: not anchored to the public chain")
		} else {
			add("chain_fields", Fail, "an unchained receipt must have seq and prev_hash null")
		}
	} else {
		if r.Seq != nil && *r.Seq >= 1 && r.PrevHash != nil && Hex64Shape(*r.PrevHash) {
			add("chain_fields", Pass, "seq "+strconv.FormatInt(*r.Seq, 10))
		} else {
			add("chain_fields", Fail, "a chained receipt needs seq >= 1 and a hex prev_hash")
		}
	}
	return res
}
