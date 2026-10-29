package mpc

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

const keyShareVersion = 1

// KeyShare is one party's output of distributed key generation. It contains
// that party's secret share Xi and Paillier key: treat it as secret and only
// persist it encrypted (see internal/sharestore).
type KeyShare struct {
	Version   int                       `json:"version"`
	Party     string                    `json:"party"`
	Committee []string                  `json:"committee"`
	Quorum    int                       `json:"quorum"`
	Data      keygen.LocalPartySaveData `json:"data"`
}

// PublicKey returns the joint ECDSA public key shared by every party.
func (k *KeyShare) PublicKey() *ecdsa.PublicKey {
	return k.Data.ECDSAPub.ToECDSAPubKey()
}

// PublicKeyBytes returns the 33-byte compressed SEC1 public key.
func (k *KeyShare) PublicKeyBytes() []byte {
	return ethcrypto.CompressPubkey(k.PublicKey())
}

// Validate checks internal consistency of a share, including that the secret
// share matches this party's public commitment (Xi·G == BigXi).
func (k *KeyShare) Validate() error {
	if k.Version != keyShareVersion {
		return fmt.Errorf("mpc: unsupported key share version %d", k.Version)
	}
	c, err := newCommittee(k.Committee)
	if err != nil {
		return err
	}
	if k.Quorum < 2 || k.Quorum > len(k.Committee) {
		return fmt.Errorf("mpc: invalid quorum %d for committee of %d", k.Quorum, len(k.Committee))
	}
	self, ok := c.ids[k.Party]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownParty, k.Party)
	}
	d := &k.Data
	if d.Xi == nil || d.ShareID == nil || d.ECDSAPub == nil || !d.Validate() {
		return errors.New("mpc: key share is missing secret or public data")
	}
	if len(d.Ks) != len(k.Committee) || len(d.BigXj) != len(k.Committee) {
		return errors.New("mpc: key share committee size mismatch")
	}
	idx := -1
	for i, name := range k.Committee {
		if d.Ks[i] == nil || d.Ks[i].Cmp(c.ids[name].KeyInt()) != 0 {
			return fmt.Errorf("mpc: key share index %d does not match committee member %q", i, name)
		}
		if name == k.Party {
			idx = i
		}
	}
	if d.ShareID.Cmp(self.KeyInt()) != 0 {
		return errors.New("mpc: share id does not match party")
	}
	if !tss.SameCurve(d.ECDSAPub.Curve(), tss.S256()) || !d.ECDSAPub.IsOnCurve() {
		return errors.New("mpc: joint public key is not on secp256k1")
	}
	if !crypto.ScalarBaseMult(tss.S256(), d.Xi).Equals(d.BigXj[idx]) {
		return errors.New("mpc: secret share does not match its public commitment")
	}
	return nil
}

// Marshal encodes the share as JSON. The result is secret.
func (k *KeyShare) Marshal() ([]byte, error) { return json.Marshal(k) }

func UnmarshalKeyShare(b []byte) (*KeyShare, error) {
	var k KeyShare
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, fmt.Errorf("mpc: decode key share: %w", err)
	}
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return &k, nil
}
