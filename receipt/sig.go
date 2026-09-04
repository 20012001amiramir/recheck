package receipt

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"

	"github.com/20012001amiramir/recheck/internal/schema"
	"github.com/20012001amiramir/recheck/merkle"
)

// DecodeKey returns the 32 raw bytes of a pubkey-b64 (§3). The base64 must be canonical: the
// standard alphabet, exact padding, zero trailing bits — one key, one spelling.
func DecodeKey(b64 string) ([]byte, error) { return schema.DecodeKey(b64) }

// DecodeSignature returns the 64 raw bytes of a canonical sig-b64 (§3).
func DecodeSignature(b64 string) ([]byte, error) { return schema.DecodeSignature(b64) }

// EncodeKey is the pubkey-b64 form of 32 raw bytes.
func EncodeKey(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

// VerifySignature checks an Ed25519 signature over the 32 raw bytes of selfHash (§3). Any decoding
// failure is false, never an error.
func VerifySignature(pubKeyB64, selfHash, sigB64 string) bool {
	pub, err := DecodeKey(pubKeyB64)
	if err != nil {
		return false
	}
	return VerifyRaw(pub, selfHash, sigB64)
}

// VerifyRaw is VerifySignature with an already decoded public key.
func VerifyRaw(pub []byte, selfHash, sigB64 string) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	msg, ok := merkle.ParseHash(selfHash)
	if !ok {
		return false
	}
	sig, err := DecodeSignature(sigB64)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// Sign produces the sig-b64 of selfHash under priv — the same bytes the issuer would produce,
// since Ed25519 is deterministic.
func Sign(priv ed25519.PrivateKey, selfHash string) (string, error) {
	msg, ok := merkle.ParseHash(selfHash)
	if !ok {
		return "", errors.New("expected a hex64 self_hash to sign")
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)), nil
}
