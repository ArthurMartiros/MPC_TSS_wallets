// Package mpc wraps bnb-chain/tss-lib to run 2-of-3 threshold ECDSA key
// generation and signing over an abstract Transport.
//
// The package never reconstructs the full private key. Each party only ever
// holds its own Shamir share (Xi) and public commitments to the other shares.
package mpc

import (
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/bnb-chain/tss-lib/v2/tss"
)

// Well-known party names for the ThresholdVault committee.
const (
	PartyUser   = "user"
	PartyServer = "server"
	PartyBackup = "backup"
)

// DefaultCommittee is the ordered 3-party committee. Order matters: a party's
// position determines its tss key (position+1) and therefore its Shamir
// x-coordinate, so it must never change after keygen.
var DefaultCommittee = []string{PartyUser, PartyServer, PartyBackup}

// DefaultQuorum is the number of parties required to sign.
const DefaultQuorum = 2

var (
	ErrUnknownParty       = errors.New("mpc: unknown party")
	ErrInsufficientQuorum = errors.New("mpc: not enough signers for quorum")
	ErrNotInSession       = errors.New("mpc: local party is not part of the session")
)

// committee maps party names to tss PartyIDs with stable keys.
type committee struct {
	names []string
	ids   map[string]*tss.PartyID
}

func newCommittee(names []string) (*committee, error) {
	if len(names) < 2 {
		return nil, fmt.Errorf("mpc: committee needs at least 2 parties, got %d", len(names))
	}
	c := &committee{names: slices.Clone(names), ids: make(map[string]*tss.PartyID, len(names))}
	for i, name := range names {
		if name == "" {
			return nil, errors.New("mpc: empty party name")
		}
		if _, dup := c.ids[name]; dup {
			return nil, fmt.Errorf("mpc: duplicate party %q", name)
		}
		c.ids[name] = tss.NewPartyID(name, name, big.NewInt(int64(i+1)))
	}
	return c, nil
}

// sorted returns tss.SortedPartyIDs for the given subset of names. tss-lib
// re-indexes parties on sort, so each call produces fresh PartyID copies to
// avoid sharing mutable Index fields between sessions.
func (c *committee) sorted(subset []string) (tss.SortedPartyIDs, error) {
	unsorted := make(tss.UnSortedPartyIDs, 0, len(subset))
	seen := make(map[string]bool, len(subset))
	for _, name := range subset {
		base, ok := c.ids[name]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownParty, name)
		}
		if seen[name] {
			return nil, fmt.Errorf("mpc: duplicate signer %q", name)
		}
		seen[name] = true
		unsorted = append(unsorted, tss.NewPartyID(base.Id, base.Moniker, base.KeyInt()))
	}
	return tss.SortPartyIDs(unsorted), nil
}

func find(ids tss.SortedPartyIDs, name string) *tss.PartyID {
	for _, id := range ids {
		if id.Id == name {
			return id
		}
	}
	return nil
}
