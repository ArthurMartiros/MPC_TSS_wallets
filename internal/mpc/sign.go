package mpc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// SignConfig describes one party's view of a threshold signing session.
type SignConfig struct {
	SessionID string
	Signers   []string // the participating subset; len must be >= quorum
	Digest    []byte   // 32-byte message hash computed by the chain adapter
}

// Signature is a secp256k1 ECDSA signature with low-S and recovery id.
type Signature struct {
	R [32]byte `json:"r"`
	S [32]byte `json:"s"`
	V byte     `json:"v"` // recovery id: 0 or 1
}

// Bytes returns the 65-byte r || s || v encoding used by go-ethereum.
func (s Signature) Bytes() []byte {
	out := make([]byte, 0, 65)
	out = append(out, s.R[:]...)
	out = append(out, s.S[:]...)
	return append(out, s.V)
}

// Verify checks the signature against pub with standard ECDSA verification
// and, independently, by recovering the public key from (r, s, v).
func (s Signature) Verify(pub *ecdsa.PublicKey, digest []byte) error {
	if len(digest) != 32 {
		return errors.New("mpc: digest must be 32 bytes")
	}
	r, sv := new(big.Int).SetBytes(s.R[:]), new(big.Int).SetBytes(s.S[:])
	if !ecdsa.Verify(pub, digest, r, sv) {
		return errors.New("mpc: signature does not verify")
	}
	recovered, err := ethcrypto.Ecrecover(digest, s.Bytes())
	if err != nil {
		return fmt.Errorf("mpc: recover public key: %w", err)
	}
	if !bytes.Equal(recovered, ethcrypto.FromECDSAPub(pub)) {
		return errors.New("mpc: recovered public key does not match")
	}
	return nil
}

// Sign runs threshold signing for the local party. Every party listed in
// cfg.Signers must call Sign concurrently with the same SessionID and Digest.
// The returned signature has already been verified against the joint key.
func Sign(ctx context.Context, cfg SignConfig, share *KeyShare, tr Transport) (*Signature, error) {
	if share == nil {
		return nil, errors.New("mpc: nil key share")
	}
	if err := share.Validate(); err != nil {
		return nil, err
	}
	if cfg.SessionID == "" {
		return nil, errors.New("mpc: sign requires a session id")
	}
	if len(cfg.Digest) != 32 {
		return nil, fmt.Errorf("mpc: digest must be 32 bytes, got %d", len(cfg.Digest))
	}
	if len(cfg.Signers) < share.Quorum {
		return nil, fmt.Errorf("%w: have %d, need %d", ErrInsufficientQuorum, len(cfg.Signers), share.Quorum)
	}
	c, err := newCommittee(share.Committee)
	if err != nil {
		return nil, err
	}
	ids, err := c.sorted(cfg.Signers)
	if err != nil {
		return nil, err
	}
	self := find(ids, share.Party)
	if self == nil {
		return nil, fmt.Errorf("%w: %q", ErrNotInSession, share.Party)
	}

	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(ids), self, len(ids), share.Quorum-1)
	s := newSession(cfg.SessionID, self, ids, tr)
	end := make(chan *common.SignatureData, 1)
	msg := new(big.Int).SetBytes(cfg.Digest)

	var party tss.Party
	if err := callTSS(func() *tss.Error {
		party = signing.NewLocalParty(msg, params, share.Data, s.out, end, len(cfg.Digest))
		return nil
	}); err != nil {
		return nil, err
	}

	data, err := run(ctx, s, party, end)
	if err != nil {
		return nil, fmt.Errorf("mpc: sign: %w", err)
	}
	if len(data.R) != 32 || len(data.S) != 32 || len(data.SignatureRecovery) != 1 {
		return nil, errors.New("mpc: malformed signature from tss-lib")
	}
	if !bytes.Equal(data.M, cfg.Digest) {
		return nil, errors.New("mpc: tss-lib signed a different message")
	}
	sig := &Signature{V: data.SignatureRecovery[0]}
	copy(sig.R[:], data.R)
	copy(sig.S[:], data.S)
	if err := sig.Verify(share.PublicKey(), cfg.Digest); err != nil {
		return nil, err
	}
	return sig, nil
}
