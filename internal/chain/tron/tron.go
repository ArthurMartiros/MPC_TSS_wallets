// Package tron implements the TRON chain adapter (Nile testnet).
package tron

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/base58"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"thresholdvault/internal/chain"
)

// AddressPrefix is the version byte of every TRON account address.
const AddressPrefix = 0x41

// Config describes a TRON network.
type Config struct {
	ID     string
	Name   string
	Tokens []chain.Asset // TRC-20 tokens
	APIURL string
}

// Chain is the TRON adapter.
type Chain struct{ cfg Config }

func New(cfg Config) *Chain { return &Chain{cfg: cfg} }

func (c *Chain) ID() string           { return c.cfg.ID }
func (c *Chain) Name() string         { return c.cfg.Name }
func (c *Chain) Family() chain.Family { return chain.FamilyTron }
func (c *Chain) Assets() []chain.Asset {
	return append([]chain.Asset{{Symbol: "TRX", Decimals: 6, Standard: "native"}}, c.cfg.Tokens...)
}

// Address returns the base58check TRON address: 0x41 || keccak256(pub)[12:].
func (c *Chain) Address(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil {
		return "", errors.New("tron: nil public key")
	}
	return EncodeAddress(ethcrypto.PubkeyToAddress(*pub).Bytes()), nil
}

// EncodeAddress turns a 20-byte account hash into a base58check address.
func EncodeAddress(h20 []byte) string { return base58.CheckEncode(h20, AddressPrefix) }

// DecodeAddress returns the 20-byte account hash of a base58check address.
func DecodeAddress(addr string) ([]byte, error) {
	h, version, err := base58.CheckDecode(addr)
	if err != nil {
		return nil, fmt.Errorf("tron: invalid address %q: %w", addr, err)
	}
	if version != AddressPrefix || len(h) != 20 {
		return nil, fmt.Errorf("tron: %q is not a TRON account address", addr)
	}
	return h, nil
}

func (c *Chain) ValidateAddress(addr string) error {
	_, err := DecodeAddress(addr)
	return err
}
