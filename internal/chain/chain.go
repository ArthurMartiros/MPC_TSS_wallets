// Package chain defines the chain-adapter abstraction. Each supported
// network lives in a subpackage (evm, utxo, tron) and the default registry
// is assembled in package networks.
package chain

import (
	"crypto/ecdsa"
	"fmt"
	"sort"
)

// Family groups chains that share transaction formats.
type Family string

const (
	FamilyEVM  Family = "evm"
	FamilyUTXO Family = "utxo"
	FamilyTron Family = "tron"
)

// Asset is a native coin or token on a chain.
type Asset struct {
	Symbol   string `json:"symbol"`
	Decimals uint8  `json:"decimals"`
	// Contract is empty for the native coin.
	Contract string `json:"contract,omitempty"`
	// Standard is "native", "erc20", "bep20" or "trc20".
	Standard string `json:"standard"`
}

// IsNative reports whether the asset is the chain's native coin.
func (a Asset) IsNative() bool { return a.Contract == "" }

// Chain is the minimal adapter every network implements. Families add
// transaction building on top (see the evm, utxo and tron packages).
type Chain interface {
	ID() string
	Name() string
	Family() Family
	Assets() []Asset
	// Address derives the wallet's receive address from the joint public key.
	Address(pub *ecdsa.PublicKey) (string, error)
	ValidateAddress(addr string) error
}

// FindAsset looks up an asset by symbol on c.
func FindAsset(c Chain, symbol string) (Asset, error) {
	for _, a := range c.Assets() {
		if a.Symbol == symbol {
			return a, nil
		}
	}
	return Asset{}, fmt.Errorf("chain %s: unsupported asset %q", c.ID(), symbol)
}

// Registry is an ordered set of chains.
type Registry struct {
	chains map[string]Chain
}

func NewRegistry(chains ...Chain) *Registry {
	r := &Registry{chains: map[string]Chain{}}
	for _, c := range chains {
		r.chains[c.ID()] = c
	}
	return r
}

func (r *Registry) Get(id string) (Chain, error) {
	c, ok := r.chains[id]
	if !ok {
		return nil, fmt.Errorf("unknown chain %q", id)
	}
	return c, nil
}

// All returns the chains sorted by ID.
func (r *Registry) All() []Chain {
	out := make([]Chain, 0, len(r.chains))
	for _, c := range r.chains {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}
