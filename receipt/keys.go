package receipt

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/20012001amiramir/recheck/canonical"
	"github.com/20012001amiramir/recheck/keys"
)

// Key purposes (§13).
const (
	PurposeReceipt = "receipt"
	PurposeRoot    = "root"
)

// Key is one pinned public key. Broken marks an entry whose public_key is not canonical base64
// of 32 bytes: it is kept so that check 4 can fail on it, because a broken pin must not pass and
// must not look like a missing one either (§13).
type Key struct {
	KeyID        string
	Purpose      string
	PublicKeyB64 string
	PublicKey    []byte
	Broken       bool
}

// KeySet is a pinned key set: one public key per key id, split by purpose (§13).
type KeySet struct {
	byID map[string]Key
}

// NewKeySet returns an empty set.
func NewKeySet() *KeySet { return &KeySet{byID: map[string]Key{}} }

// Add pins a key. A key id names one public key for all time, so the same id with a different
// key is an error.
func (s *KeySet) Add(k Key) error {
	if s.byID == nil {
		s.byID = map[string]Key{}
	}
	if k.Purpose != PurposeReceipt && k.Purpose != PurposeRoot {
		return fmt.Errorf("key %s: purpose must be receipt or root", k.KeyID)
	}
	if existing, ok := s.byID[k.KeyID]; ok {
		if existing.Broken != k.Broken || !bytes.Equal(existing.PublicKey, k.PublicKey) {
			return fmt.Errorf("key id %s is listed twice with different public keys", k.KeyID)
		}
		return nil
	}
	s.byID[k.KeyID] = k
	return nil
}

// Lookup finds the key pinned for keyID with the given purpose.
func (s *KeySet) Lookup(purpose, keyID string) (Key, bool) {
	if s == nil {
		return Key{}, false
	}
	k, ok := s.byID[keyID]
	if !ok || k.Purpose != purpose {
		return Key{}, false
	}
	return k, true
}

// Len is the number of pinned keys.
func (s *KeySet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.byID)
}

// Merge adds every key of other.
func (s *KeySet) Merge(other *KeySet) error {
	if other == nil {
		return nil
	}
	for _, k := range other.byID {
		if err := s.Add(k); err != nil {
			return err
		}
	}
	return nil
}

// ParseKeySet reads a key set. It accepts the issuer's keys.json shape ({"keys": [...]}), a bare
// array of key entries, or a single entry — each entry needing key_id and public_key, with
// purpose taken from the entry or, failing that, from the key id.
func ParseKeySet(data []byte) (*KeySet, error) {
	raw, err := canonical.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	var entries []*canonical.Value
	switch {
	case raw.Kind == canonical.Array:
		entries = raw.Array
	case raw.Kind == canonical.Object && raw.Get("keys") != nil:
		list := raw.Get("keys")
		if list.Kind != canonical.Array {
			return nil, errors.New("keys: \"keys\" must be an array")
		}
		entries = list.Array
	case raw.Kind == canonical.Object:
		entries = []*canonical.Value{raw}
	default:
		return nil, errors.New("keys: expected an object or an array")
	}
	set := NewKeySet()
	for i, e := range entries {
		k, err := keyEntry(e)
		if err != nil {
			return nil, fmt.Errorf("keys[%d]: %w", i, err)
		}
		if err := set.Add(k); err != nil {
			return nil, fmt.Errorf("keys: %w", err)
		}
	}
	return set, nil
}

func keyEntry(e *canonical.Value) (Key, error) {
	if e.Kind != canonical.Object {
		return Key{}, errors.New("expected an object")
	}
	id := e.Get("key_id")
	if id == nil || id.Kind != canonical.String || !KeyIDShape(id.Str) {
		return Key{}, errors.New("key_id must be eb-<purpose>-<name>")
	}
	pk := e.Get("public_key")
	if pk == nil || pk.Kind != canonical.String {
		return Key{}, errors.New("public_key must be a string")
	}
	raw, err := DecodeKey(pk.Str)
	broken := err != nil
	if alg := e.Get("alg"); alg != nil && (alg.Kind != canonical.String || alg.Str != "ed25519") {
		return Key{}, errors.New("alg must be ed25519")
	}
	purpose := ""
	if p := e.Get("purpose"); p != nil {
		if p.Kind != canonical.String {
			return Key{}, errors.New("purpose must be a string")
		}
		purpose = p.Str
	} else if strings.HasPrefix(id.Str, "eb-root-") {
		purpose = PurposeRoot
	} else {
		purpose = PurposeReceipt
	}
	return Key{KeyID: id.Str, Purpose: purpose, PublicKeyB64: pk.Str, PublicKey: raw, Broken: broken}, nil
}

// LoadKeySet reads a key set from a file.
func LoadKeySet(path string) (*KeySet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseKeySet(data)
}

var (
	pinnedOnce sync.Once
	pinnedSet  *KeySet
	pinnedErr  error
)

// Pinned is the key set compiled into this build from keys/exhibitb.json. It is empty until the
// deploy step fills the file; an empty set makes key_pinned skip, never pass.
func Pinned() (*KeySet, error) {
	pinnedOnce.Do(func() {
		pinnedSet, pinnedErr = ParseKeySet(keys.Pinned)
	})
	if pinnedErr != nil {
		return nil, pinnedErr
	}
	// A copy, so callers may merge --keys into it without touching the compiled set.
	out := NewKeySet()
	_ = out.Merge(pinnedSet)
	return out, nil
}
