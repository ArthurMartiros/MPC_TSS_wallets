package mpc

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// KeygenConfig describes one party's view of a DKG session.
type KeygenConfig struct {
	SessionID string
	Self      string
	Committee []string // ordered; defaults to DefaultCommittee
	Quorum    int      // signers required; defaults to DefaultQuorum
	// PreParams are this party's Paillier/safe-prime parameters. Required:
	// generating them inline takes minutes, so callers precompute them with
	// GeneratePreParams and must use a fresh set for every keygen.
	PreParams *keygen.LocalPreParams
}

// GeneratePreParams computes the Paillier key and safe primes a party needs
// for one key generation. This is CPU-heavy (seconds to minutes).
func GeneratePreParams(ctx context.Context) (*keygen.LocalPreParams, error) {
	return keygen.GeneratePreParamsWithContext(ctx)
}

// Keygen runs distributed key generation for the local party and returns its
// key share. Every committee member must run Keygen concurrently with the same
// SessionID, Committee and Quorum.
func Keygen(ctx context.Context, cfg KeygenConfig, tr Transport) (*KeyShare, error) {
	if cfg.Committee == nil {
		cfg.Committee = DefaultCommittee
	}
	if cfg.Quorum == 0 {
		cfg.Quorum = DefaultQuorum
	}
	if cfg.SessionID == "" {
		return nil, errors.New("mpc: keygen requires a session id")
	}
	if cfg.Quorum < 2 || cfg.Quorum > len(cfg.Committee) {
		return nil, fmt.Errorf("mpc: invalid quorum %d for committee of %d", cfg.Quorum, len(cfg.Committee))
	}
	if cfg.PreParams == nil || !cfg.PreParams.ValidateWithProof() {
		return nil, errors.New("mpc: keygen requires valid pre-parameters")
	}
	c, err := newCommittee(cfg.Committee)
	if err != nil {
		return nil, err
	}
	ids, err := c.sorted(cfg.Committee)
	if err != nil {
		return nil, err
	}
	self := find(ids, cfg.Self)
	if self == nil {
		return nil, fmt.Errorf("%w: %q", ErrNotInSession, cfg.Self)
	}

	// tss-lib's threshold t means t+1 parties are needed to sign.
	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(ids), self, len(ids), cfg.Quorum-1)
	params.SetSafePrimeGenTimeout(5 * time.Minute)

	s := newSession(cfg.SessionID, self, ids, tr)
	end := make(chan *keygen.LocalPartySaveData, 1)
	var party tss.Party
	if err := callTSS(func() *tss.Error {
		party = keygen.NewLocalParty(params, s.out, end, *cfg.PreParams)
		return nil
	}); err != nil {
		return nil, err
	}

	data, err := run(ctx, s, party, end)
	if err != nil {
		return nil, fmt.Errorf("mpc: keygen: %w", err)
	}
	share := &KeyShare{
		Version:   keyShareVersion,
		Party:     cfg.Self,
		Committee: slices.Clone(cfg.Committee),
		Quorum:    cfg.Quorum,
		Data:      *data,
	}
	if err := share.Validate(); err != nil {
		return nil, fmt.Errorf("mpc: keygen produced invalid share: %w", err)
	}
	return share, nil
}
