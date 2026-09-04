// Package chain holds the chain rules of spec §6–§7 and replays an exported chain: a JSONL file
// with one sealed receipt per line, in seq order.
package chain

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/20012001amiramir/recheck/canonical"
	"github.com/20012001amiramir/recheck/receipt"
)

// Genesis is sha256("exhibitb.genesis.v1") (§6): the prev_hash of the receipt at seq 1 and the
// prev_root of the first root file.
const Genesis = "3058620acf7ca95f8cc2c8970e7fc04afdbdeab9e688603bdd2e03a3bfcb588f"

// Link checks that next follows prev in the chain (§7): seq is dense and prev_hash is the
// previous self_hash. A nil prev means next must be the first receipt, at seq 1 pointing at the
// genesis constant.
func Link(prev, next *receipt.Receipt) error {
	if next == nil || next.Seq == nil || next.PrevHash == nil {
		return errors.New("not a chained receipt")
	}
	if prev == nil {
		if *next.Seq != 1 {
			return fmt.Errorf("seq %d without a predecessor", *next.Seq)
		}
		if *next.PrevHash != Genesis {
			return errors.New("seq 1 does not point at the genesis constant")
		}
		return nil
	}
	if prev.Seq == nil {
		return errors.New("predecessor is not a chained receipt")
	}
	if *next.Seq != *prev.Seq+1 {
		return fmt.Errorf("seq %d does not follow seq %d", *next.Seq, *prev.Seq)
	}
	if *next.PrevHash != prev.SelfHash {
		return fmt.Errorf("seq %d prev_hash does not equal the self_hash of seq %d", *next.Seq, *prev.Seq)
	}
	return nil
}

// Break is the first place a replay broke, with the reasons of GET /chain/verify (§7.1):
// prev_hash, self_hash (a receipt that no longer hashes to its self_hash, or does not parse at
// all), signature.
type Break struct {
	Seq    int64  `json:"seq"`
	Line   int    `json:"line"`
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}

// Report is the outcome of a replay.
type Report struct {
	OK          bool   `json:"ok"`
	Checked     int    `json:"checked"`
	FirstSeq    int64  `json:"first_seq"`
	HeadSeq     int64  `json:"head_seq"`
	HeadHash    string `json:"head_hash"`
	FirstBroken *Break `json:"first_broken"`
	// FromGenesis is true when the file starts at seq 1, so the first link was checked against
	// the genesis constant; a later segment can only be checked internally.
	FromGenesis bool `json:"from_genesis"`
}

// Replay walks receipts read from r — one JSON receipt per line — and re-derives what can be
// re-derived: each self_hash from the receipt's canonical body, each prev_hash from the receipt
// before it, and each issuer signature. With a pinned key set the signature is checked under the
// pinned key for its key_id and the embedded key must equal it, as the issuer's own replay does;
// without one it is checked under the embedded key only.
func Replay(r io.Reader, keys *receipt.KeySet) Report {
	rep := Report{OK: true, HeadHash: Genesis}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	var prev *receipt.Receipt
	line := 0
	for sc.Scan() {
		line++
		text := bytes.TrimSpace(sc.Bytes())
		if len(text) == 0 {
			continue
		}
		rec, raw, err := receipt.Parse(text)
		if err != nil || rec.Projected {
			seq := int64(0)
			if raw != nil {
				if s := raw.Get("seq"); s != nil && s.Kind == canonical.Number && s.IsInt {
					seq = s.Int
				}
			}
			detail := "the receipt does not parse"
			if err != nil {
				detail = err.Error()
			} else {
				detail = "a projection cannot be replayed: the sealed body is not present"
			}
			return broken(rep, seq, line, "self_hash", detail)
		}
		if rec.Seq == nil || rec.PrevHash == nil {
			return broken(rep, 0, line, "prev_hash", "an unchained receipt has no place in the chain")
		}
		seq := *rec.Seq
		if prev == nil {
			rep.FirstSeq = seq
			rep.FromGenesis = seq == 1
			if seq == 1 && *rec.PrevHash != Genesis {
				return broken(rep, seq, line, "prev_hash", "seq 1 does not point at the genesis constant")
			}
		} else if err := Link(prev, rec); err != nil {
			return broken(rep, seq, line, "prev_hash", err.Error())
		}
		computed, err := canonical.SelfHash(raw)
		if err != nil || computed != rec.SelfHash {
			return broken(rep, seq, line, "self_hash", "computed "+computed+", receipt says "+rec.SelfHash)
		}
		if reason := signatureProblem(rec, keys); reason != "" {
			return broken(rep, seq, line, "signature", reason)
		}
		rep.Checked++
		rep.HeadSeq = seq
		rep.HeadHash = rec.SelfHash
		prev = rec
	}
	if err := sc.Err(); err != nil {
		return broken(rep, rep.HeadSeq, line, "self_hash", "read error: "+err.Error())
	}
	return rep
}

func broken(rep Report, seq int64, line int, reason, detail string) Report {
	rep.OK = false
	rep.FirstBroken = &Break{Seq: seq, Line: line, Reason: reason, Detail: detail}
	return rep
}

func signatureProblem(rec *receipt.Receipt, keys *receipt.KeySet) string {
	sigs := rec.IssuerSignatures()
	if len(sigs) != 1 {
		return strconv.Itoa(len(sigs)) + " issuer signatures, expected exactly one"
	}
	sig := sigs[0]
	if sig.KeyID != rec.Issuer.KeyID {
		return "signature key_id " + sig.KeyID + " is not the issuer's " + rec.Issuer.KeyID
	}
	embedded, err := receipt.DecodeKey(rec.Issuer.PublicKey)
	if err != nil {
		return "issuer public key: " + err.Error()
	}
	pub := embedded
	if keys.Len() > 0 {
		pinned, ok := keys.Lookup(receipt.PurposeReceipt, rec.Issuer.KeyID)
		switch {
		case !ok:
			return "key " + rec.Issuer.KeyID + " is not in the pinned set"
		case pinned.Broken:
			return "the pinned entry for " + rec.Issuer.KeyID + " is broken"
		case !bytes.Equal(pinned.PublicKey, embedded):
			return "the embedded key differs from the pinned key for " + rec.Issuer.KeyID
		}
		pub = pinned.PublicKey
	}
	if !receipt.VerifyRaw(pub, rec.SelfHash, sig.Sig) {
		return "ed25519 signature by " + sig.KeyID + " does not verify"
	}
	return ""
}

// ReplayFile is Replay over a file.
func ReplayFile(path string, keys *receipt.KeySet) (Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return Report{}, err
	}
	defer f.Close()
	return Replay(f, keys), nil
}
