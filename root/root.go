// Package root reads and checks daily root files (spec §9) and inclusion proofs (§10).
package root

import (
	"strconv"

	"github.com/20012001amiramir/recheck/canonical"
	"github.com/20012001amiramir/recheck/internal/schema"
	"github.com/20012001amiramir/recheck/merkle"
	"github.com/20012001amiramir/recheck/receipt"
)

// Kind is the literal kind of a root file.
const Kind = "exhibitb.root"

// File is a root file v1 (§9).
type File struct {
	V          int64
	Kind       string
	Date       string
	FirstSeq   *int64
	LastSeq    *int64
	Count      int64
	Root       string
	PrevRoot   string
	HeadHash   string
	KeyID      string
	SelfHash   string
	Signatures []Signature
}

// Signature is a root-file signature entry: no role.
type Signature struct {
	KeyID string
	Alg   string
	Sig   string
}

// Parse reads and validates a root file. The error is a *canonical.Error for text that is not
// JSON and a *schema.Error for JSON of the wrong shape.
func Parse(data []byte) (*File, *canonical.Value, error) {
	raw, err := canonical.Parse(data)
	if err != nil {
		return nil, nil, err
	}
	f, err := FromValue(raw)
	return f, raw, err
}

// FromValue validates a parsed JSON value as a root file.
func FromValue(raw *canonical.Value) (*File, error) {
	v := &schema.Validator{}
	f := &File{}
	o := v.Object("$", raw)
	f.V = o.LiteralInt("v", 1)
	f.Kind = o.Literal("kind", Kind)
	f.Date = o.Str("date", schema.Date)
	f.FirstSeq = o.IntOrNull("first_seq", 1, canonical.MaxSafeInteger)
	f.LastSeq = o.IntOrNull("last_seq", 1, canonical.MaxSafeInteger)
	f.Count = o.Int("count", 0, canonical.MaxSafeInteger)
	f.Root = o.Str("root", schema.Hex64)
	f.PrevRoot = o.Str("prev_root", schema.Hex64)
	f.HeadHash = o.Str("head_hash", schema.Hex64)
	f.KeyID = o.Str("key_id", schema.KeyID)
	f.SelfHash = o.Str("self_hash", schema.Hex64)
	sigsPath, sigs := o.Array("signatures", receipt.MaxSignatures)
	for i, s := range sigs {
		so := v.Object(sigsPath+"["+strconv.Itoa(i)+"]", s)
		f.Signatures = append(f.Signatures, Signature{
			KeyID: so.Str("key_id", schema.KeyID),
			Alg:   so.Literal("alg", "ed25519"),
			Sig:   so.Str("sig", schema.SigB64),
		})
		so.Done()
	}
	o.Done()
	if err := v.Err(); err != nil {
		return nil, err
	}
	return f, nil
}

// Verify runs the three root-file checks of §12 — root_schema, root_self_hash, root_signature
// (§9 rule 4) — against the pinned root keys. The file carries no key, so an unpinned root key
// is a root_signature failure. The parsed file is nil when the schema check failed.
func Verify(data []byte, keys *receipt.KeySet) (*File, []receipt.Check) {
	var checks []receipt.Check
	add := func(name, status, detail string) {
		checks = append(checks, receipt.Check{Name: name, Status: status, Detail: detail})
	}

	f, raw, err := Parse(data)
	if err != nil {
		detail := err.Error()
		if ce, ok := err.(*canonical.Error); ok {
			detail = ce.Path + ": " + ce.Msg
		}
		add("root_schema", receipt.Fail, detail)
		add("root_self_hash", receipt.Skip, "root schema failed")
		add("root_signature", receipt.Skip, "root schema failed")
		return nil, checks
	}
	add("root_schema", receipt.Pass, "root file v1 for "+f.Date+", "+strconv.FormatInt(f.Count, 10)+" leaves")

	computed, herr := canonical.SelfHash(raw)
	switch {
	case herr != nil:
		add("root_self_hash", receipt.Fail, "could not canonicalize: "+herr.Error())
	case computed == f.SelfHash:
		add("root_self_hash", receipt.Pass, f.SelfHash)
	default:
		add("root_self_hash", receipt.Fail, "computed "+computed+", root file says "+f.SelfHash)
	}

	pinned, ok := keys.Lookup(receipt.PurposeRoot, f.KeyID)
	switch {
	case len(f.Signatures) == 0:
		add("root_signature", receipt.Fail, "no signature")
	case f.Signatures[0].KeyID != f.KeyID:
		add("root_signature", receipt.Fail, "first signature key_id "+f.Signatures[0].KeyID+" is not the file's "+f.KeyID)
	case !ok:
		add("root_signature", receipt.Fail, "root key "+f.KeyID+" is not pinned and the file carries no key, so the signature cannot be checked")
	case pinned.Broken:
		add("root_signature", receipt.Fail, "the pinned entry for "+f.KeyID+" is not canonical base64 of 32 bytes: the pin itself is broken")
	case receipt.VerifyRaw(pinned.PublicKey, f.SelfHash, f.Signatures[0].Sig):
		add("root_signature", receipt.Pass, "ed25519 by "+f.KeyID)
	default:
		add("root_signature", receipt.Fail, "ed25519 signature by "+f.KeyID+" does not verify over self_hash")
	}
	return f, checks
}

// Proof is the answer of GET /api/receipt/<id>/proof (§10): an inclusion proof, or a status of
// "pending" (the day is not rooted yet) or "unchained" (no proof will ever exist).
type Proof struct {
	Status    string
	RootsAt   *string
	ReceiptID string
	SelfHash  string
	Seq       *int64
	Date      string
	LeafIndex int64
	TreeSize  int64
	Root      string
	AuditPath []string
	RootFile  string
}

// ParseProof reads a proof. Members the verifier does not need (receipt_id, seq, date, root_file)
// are optional, and unknown members are ignored: this is the issuer's API answer, not a hashed
// document.
func ParseProof(data []byte) (*Proof, error) {
	raw, err := canonical.Parse(data)
	if err != nil {
		return nil, err
	}
	v := &schema.Validator{}
	p := &Proof{}
	o := v.Object("$", raw)
	if _, status := o.Optional("status"); status != nil {
		p.Status = o.Enum("status", "pending", "unchained")
		if _, at := o.Optional("roots_at"); at != nil {
			p.RootsAt = o.StrOrNull("roots_at", schema.Timestamp)
		}
		if err := v.Err(); err != nil {
			return nil, err
		}
		return p, nil
	}
	if _, id := o.Optional("receipt_id"); id != nil {
		p.ReceiptID = o.Str("receipt_id", schema.ReceiptID)
	}
	p.SelfHash = o.Str("self_hash", schema.Hex64)
	if _, seq := o.Optional("seq"); seq != nil {
		n := o.Int("seq", 1, canonical.MaxSafeInteger)
		p.Seq = &n
	}
	if _, date := o.Optional("date"); date != nil {
		p.Date = o.Str("date", schema.Date)
	}
	p.LeafIndex = o.Int("leaf_index", 0, canonical.MaxSafeInteger)
	p.TreeSize = o.Int("tree_size", 1, canonical.MaxSafeInteger)
	p.Root = o.Str("root", schema.Hex64)
	pathPath, entries := o.Array("audit_path", 64)
	for i, e := range entries {
		if e.Kind != canonical.String || schema.Hex64(e.Str) != "" {
			v.Fail(pathPath+"["+strconv.Itoa(i)+"]", "expected a lowercase hex sha256")
			break
		}
		p.AuditPath = append(p.AuditPath, e.Str)
	}
	if _, rf := o.Optional("root_file"); rf != nil {
		p.RootFile = o.Str("root_file", func(string) string { return "" })
	}
	if err := v.Err(); err != nil {
		return nil, err
	}
	return p, nil
}

// Inclusion is the `inclusion` check of §10: the proof must be for this receipt (its id when
// present, its self_hash), point at this root file (same root and count, same date when given),
// and rebuild the root from the leaf. file is nil when the root file failed its schema, and
// receiptSelfHash is empty when the receipt failed its schema; either makes the check skip, since
// the failure is already reported elsewhere.
func Inclusion(proofData []byte, file *File, receiptID, receiptSelfHash string) receipt.Check {
	check := func(status, detail string) receipt.Check {
		return receipt.Check{Name: "inclusion", Status: status, Detail: detail}
	}
	p, err := ParseProof(proofData)
	if err != nil {
		detail := err.Error()
		if ce, ok := err.(*canonical.Error); ok {
			detail = ce.Path + ": " + ce.Msg
		}
		return check(receipt.Fail, "proof: "+detail)
	}
	switch p.Status {
	case "pending":
		detail := "proof pending: the receipt's day is not rooted yet"
		if p.RootsAt != nil {
			detail += " (roots at " + *p.RootsAt + ")"
		}
		return check(receipt.Warn, detail)
	case "unchained":
		return check(receipt.Skip, "unchained receipt: it has no place in any tree")
	}
	if receiptSelfHash == "" {
		return check(receipt.Skip, "receipt schema failed")
	}
	if file == nil {
		return check(receipt.Skip, "root file did not pass its schema")
	}
	switch {
	case p.ReceiptID != "" && receiptID != "" && p.ReceiptID != receiptID:
		return check(receipt.Fail, "proof is for receipt "+p.ReceiptID+", not "+receiptID)
	case p.SelfHash != receiptSelfHash:
		return check(receipt.Fail, "proof is for self_hash "+p.SelfHash+", the receipt's is "+receiptSelfHash)
	case p.Root != file.Root:
		return check(receipt.Fail, "proof root "+p.Root+" is not the root file's "+file.Root)
	case p.TreeSize != file.Count:
		return check(receipt.Fail, "proof tree_size "+strconv.FormatInt(p.TreeSize, 10)+" is not the root file's count "+strconv.FormatInt(file.Count, 10))
	case p.Date != "" && p.Date != file.Date:
		return check(receipt.Fail, "proof is for "+p.Date+", the root file is for "+file.Date)
	case p.LeafIndex >= p.TreeSize:
		return check(receipt.Fail, "leaf_index "+strconv.FormatInt(p.LeafIndex, 10)+" is outside a tree of "+strconv.FormatInt(p.TreeSize, 10))
	case !merkle.VerifyInclusionHex(p.SelfHash, int(p.LeafIndex), int(p.TreeSize), p.AuditPath, p.Root):
		return check(receipt.Fail, "the audit path does not rebuild the root from leaf "+strconv.FormatInt(p.LeafIndex, 10))
	}
	return check(receipt.Pass, "leaf "+strconv.FormatInt(p.LeafIndex, 10)+" of "+strconv.FormatInt(p.TreeSize, 10)+" in the root of "+file.Date)
}
