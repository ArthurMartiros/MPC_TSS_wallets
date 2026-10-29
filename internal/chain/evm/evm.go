// Package evm implements the chain adapter for Ethereum-compatible networks
// (Ethereum Sepolia, BNB Smart Chain testnet).
package evm

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"thresholdvault/internal/chain"
)

// Config describes one EVM network.
type Config struct {
	ID         string
	Name       string
	ChainID    *big.Int
	Native     chain.Asset
	TokenStd   string // "erc20" or "bep20"
	Tokens     []chain.Asset
	RPCURL     string
	ExplorerTx string // printf pattern for a tx hash, e.g. https://sepolia.etherscan.io/tx/%s
}

// Chain is an EVM chain adapter.
type Chain struct {
	cfg Config
}

func New(cfg Config) *Chain { return &Chain{cfg: cfg} }

func (c *Chain) ID() string            { return c.cfg.ID }
func (c *Chain) Name() string          { return c.cfg.Name }
func (c *Chain) Family() chain.Family  { return chain.FamilyEVM }
func (c *Chain) Config() Config        { return c.cfg }
func (c *Chain) ChainID() *big.Int     { return new(big.Int).Set(c.cfg.ChainID) }
func (c *Chain) Assets() []chain.Asset { return append([]chain.Asset{c.cfg.Native}, c.cfg.Tokens...) }

// Address returns the EIP-55 checksummed address of pub.
func (c *Chain) Address(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil {
		return "", errors.New("evm: nil public key")
	}
	return ethcrypto.PubkeyToAddress(*pub).Hex(), nil
}

// ValidateAddress accepts 0x-prefixed hex addresses. Mixed-case input must
// carry a valid EIP-55 checksum; all-lower or all-upper input is accepted.
func (c *Chain) ValidateAddress(addr string) error {
	_, err := ParseAddress(addr)
	return err
}

// ParseAddress parses and checksum-validates an EVM address.
func ParseAddress(addr string) (common.Address, error) {
	if len(addr) != 42 || addr[:2] != "0x" || !common.IsHexAddress(addr) {
		return common.Address{}, fmt.Errorf("evm: invalid address %q", addr)
	}
	a := common.HexToAddress(addr)
	body := addr[2:]
	if body != lower(body) && body != upper(body) && a.Hex() != addr {
		return common.Address{}, fmt.Errorf("evm: bad EIP-55 checksum in %q", addr)
	}
	if a == (common.Address{}) {
		return common.Address{}, errors.New("evm: refusing the zero address")
	}
	return a, nil
}

func lower(s string) string {
	b := []byte(s)
	for i, ch := range b {
		if ch >= 'A' && ch <= 'F' {
			b[i] = ch + 32
		}
	}
	return string(b)
}

func upper(s string) string {
	b := []byte(s)
	for i, ch := range b {
		if ch >= 'a' && ch <= 'f' {
			b[i] = ch - 32
		}
	}
	return string(b)
}
