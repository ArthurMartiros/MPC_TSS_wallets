// Package identity holds a signer's long-term keys: Ed25519 for
// authenticating protocol messages and X25519 (NaCl box) for encrypting them
// end to end, so the relay in between learns nothing and can't forge or
// tamper with anything.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const publicPrefix = "tvid1:"

// Public is the shareable half of an identity. Peers pin it out of band.
type Public struct {
	Name    string
	SignKey ed25519.PublicKey
	BoxKey  [32]byte
}

// Identity is a signer's private identity. It is secret.
type Identity struct {
	Public
	signPriv ed25519.PrivateKey
	boxPriv  [32]byte
}

// Generate creates a fresh identity for name.
func Generate(name string) (*Identity, error) {
	if name == "" || strings.ContainsAny(name, ": \t\n") {
		return nil, fmt.Errorf("identity: invalid name %q", name)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	boxPub, boxPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{
		Public:   Public{Name: name, SignKey: signPub, BoxKey: *boxPub},
		signPriv: signPriv,
		boxPriv:  *boxPriv,
	}, nil
}

// Sign signs msg with the Ed25519 key.
func (id *Identity) Sign(msg []byte) []byte { return ed25519.Sign(id.signPriv, msg) }

// Seal encrypts plaintext to recipient with NaCl box (X25519 +
// XSalsa20-Poly1305) and a random nonce.
func (id *Identity) Seal(recipient *Public, plaintext []byte) (nonce [24]byte, ciphertext []byte, err error) {
	if _, err = rand.Read(nonce[:]); err != nil {
		return nonce, nil, err
	}
	return nonce, box.Seal(nil, plaintext, &nonce, &recipient.BoxKey, &id.boxPriv), nil
}

// Open decrypts a box sealed by sender to this identity.
func (id *Identity) Open(sender *Public, nonce [24]byte, ciphertext []byte) ([]byte, error) {
	out, ok := box.Open(nil, ciphertext, &nonce, &sender.BoxKey, &id.boxPriv)
	if !ok {
		return nil, errors.New("identity: box authentication failed")
	}
	return out, nil
}

// Verify checks an Ed25519 signature made by p.
func (p *Public) Verify(msg, sig []byte) bool {
	return len(p.SignKey) == ed25519.PublicKeySize && ed25519.Verify(p.SignKey, msg, sig)
}

// String encodes the public identity as "tvid1:<name>:<base64(sign||box)>".
func (p *Public) String() string {
	raw := append(append([]byte{}, p.SignKey...), p.BoxKey[:]...)
	return publicPrefix + p.Name + ":" + base64.RawURLEncoding.EncodeToString(raw)
}

// Fingerprint is a short hash for humans to compare out of band.
func (p *Public) Fingerprint() string {
	sum := sha256.Sum256([]byte(p.String()))
	return hex.EncodeToString(sum[:8])
}

// Equal reports whether two public identities are identical.
func (p *Public) Equal(o *Public) bool { return p.String() == o.String() }

// ParsePublic decodes the output of Public.String.
func ParsePublic(s string) (*Public, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), publicPrefix)
	if !ok {
		return nil, errors.New("identity: missing tvid1 prefix")
	}
	name, enc, ok := strings.Cut(rest, ":")
	if !ok || name == "" {
		return nil, errors.New("identity: malformed public identity")
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil || len(raw) != ed25519.PublicKeySize+32 {
		return nil, errors.New("identity: malformed key material")
	}
	p := &Public{Name: name, SignKey: ed25519.PublicKey(raw[:ed25519.PublicKeySize])}
	copy(p.BoxKey[:], raw[ed25519.PublicKeySize:])
	return p, nil
}

type privateJSON struct {
	Name     string `json:"name"`
	SignSeed []byte `json:"sign_seed"`
	BoxPriv  []byte `json:"box_priv"`
}

// MarshalPrivate encodes the full identity for encrypted storage.
func (id *Identity) MarshalPrivate() ([]byte, error) {
	return json.Marshal(privateJSON{Name: id.Name, SignSeed: id.signPriv.Seed(), BoxPriv: id.boxPriv[:]})
}

// UnmarshalPrivate decodes MarshalPrivate output.
func UnmarshalPrivate(b []byte) (*Identity, error) {
	var pj privateJSON
	if err := json.Unmarshal(b, &pj); err != nil {
		return nil, fmt.Errorf("identity: decode: %w", err)
	}
	if pj.Name == "" || len(pj.SignSeed) != ed25519.SeedSize || len(pj.BoxPriv) != 32 {
		return nil, errors.New("identity: malformed private identity")
	}
	id := &Identity{signPriv: ed25519.NewKeyFromSeed(pj.SignSeed)}
	copy(id.boxPriv[:], pj.BoxPriv)
	id.Name = pj.Name
	id.SignKey = id.signPriv.Public().(ed25519.PublicKey)
	pub, err := boxPublicFromPrivate(&id.boxPriv)
	if err != nil {
		return nil, err
	}
	id.BoxKey = pub
	return id, nil
}

func boxPublicFromPrivate(priv *[32]byte) ([32]byte, error) {
	var pub [32]byte
	out, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return pub, fmt.Errorf("identity: derive box key: %w", err)
	}
	copy(pub[:], out)
	return pub, nil
}
