// Package utxo implements chain adapters for Bitcoin-derived networks:
// Bitcoin and Litecoin (native SegWit P2WPKH) and Dash (legacy P2PKH, Dash
// has no SegWit).
package utxo

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/bech32"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"thresholdvault/internal/chain"
)

// AddressType selects the wallet's script type.
type AddressType string

const (
	P2WPKH AddressType = "p2wpkh"
	P2PKH  AddressType = "p2pkh"
)

// Params describes one UTXO network.
type Params struct {
	ID          string
	Name        string
	Symbol      string
	AddressType AddressType
	Bech32HRP   string // for P2WPKH
	PubKeyHash  byte   // base58 version byte for P2PKH
	ScriptHash  byte   // base58 version byte for P2SH (validation only)
}

// Network parameters. Values come from each project's chainparams.
var (
	BitcoinTestnet = Params{ID: "bitcoin-testnet", Name: "Bitcoin Testnet", Symbol: "BTC", AddressType: P2WPKH, Bech32HRP: "tb", PubKeyHash: 0x6f, ScriptHash: 0xc4}
	// Litecoin testnet: bech32 "tltc", P2PKH 111, P2SH 58 (litecoin/src/chainparams.cpp).
	LitecoinTestnet = Params{ID: "litecoin-testnet", Name: "Litecoin Testnet", Symbol: "LTC", AddressType: P2WPKH, Bech32HRP: "tltc", PubKeyHash: 0x6f, ScriptHash: 0x3a}
	// Dash testnet: P2PKH 140 ('y'), P2SH 19 (dashpay/dash/src/chainparams.cpp).
	DashTestnet = Params{ID: "dash-testnet", Name: "Dash Testnet", Symbol: "DASH", AddressType: P2PKH, PubKeyHash: 0x8c, ScriptHash: 0x13}

	// Mainnet parameters are used only by address test vectors.
	BitcoinMainnet = Params{ID: "bitcoin-mainnet", Symbol: "BTC", AddressType: P2WPKH, Bech32HRP: "bc", PubKeyHash: 0x00, ScriptHash: 0x05}
	DashMainnet    = Params{ID: "dash-mainnet", Symbol: "DASH", AddressType: P2PKH, PubKeyHash: 0x4c, ScriptHash: 0x10}
)

// Chain is a UTXO chain adapter.
type Chain struct {
	p Params
}

func New(p Params) *Chain { return &Chain{p: p} }

func (c *Chain) ID() string           { return c.p.ID }
func (c *Chain) Name() string         { return c.p.Name }
func (c *Chain) Family() chain.Family { return chain.FamilyUTXO }
func (c *Chain) Params() Params       { return c.p }
func (c *Chain) Assets() []chain.Asset {
	return []chain.Asset{{Symbol: c.p.Symbol, Decimals: 8, Standard: "native"}}
}

// PubKeyHash returns HASH160 of the compressed public key.
func PubKeyHash(pub *ecdsa.PublicKey) []byte {
	return btcutil.Hash160(ethcrypto.CompressPubkey(pub))
}

// Address derives the wallet address for the network's address type.
func (c *Chain) Address(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil {
		return "", errors.New("utxo: nil public key")
	}
	return c.EncodePubKeyHash(PubKeyHash(pub))
}

// EncodePubKeyHash encodes a 20-byte key hash as this network's address.
func (c *Chain) EncodePubKeyHash(h []byte) (string, error) {
	if len(h) != 20 {
		return "", errors.New("utxo: key hash must be 20 bytes")
	}
	switch c.p.AddressType {
	case P2WPKH:
		conv, err := bech32.ConvertBits(h, 8, 5, true)
		if err != nil {
			return "", err
		}
		return bech32.Encode(c.p.Bech32HRP, append([]byte{0}, conv...))
	case P2PKH:
		return base58.CheckEncode(h, c.p.PubKeyHash), nil
	}
	return "", fmt.Errorf("utxo: unsupported address type %q", c.p.AddressType)
}

// DecodedAddress is a parsed destination.
type DecodedAddress struct {
	Type AddressType // P2WPKH, P2PKH or "p2sh"
	Hash []byte      // 20-byte witness program / key hash / script hash
}

// DecodeAddress parses an address of this network. Supported destinations:
// P2WPKH (bech32 v0, 20 bytes), P2PKH and P2SH (base58check).
func (c *Chain) DecodeAddress(addr string) (*DecodedAddress, error) {
	if c.p.Bech32HRP != "" {
		if hrp, data, err := bech32.Decode(addr); err == nil {
			if hrp != c.p.Bech32HRP {
				return nil, fmt.Errorf("utxo: address %q is for another network (hrp %q)", addr, hrp)
			}
			if len(data) < 1 || data[0] != 0 {
				return nil, fmt.Errorf("utxo: only segwit v0 addresses are supported")
			}
			prog, err := bech32.ConvertBits(data[1:], 5, 8, false)
			if err != nil {
				return nil, err
			}
			if len(prog) != 20 {
				return nil, fmt.Errorf("utxo: only P2WPKH (20-byte) witness programs are supported")
			}
			return &DecodedAddress{Type: P2WPKH, Hash: prog}, nil
		}
	}
	h, version, err := base58.CheckDecode(addr)
	if err != nil {
		return nil, fmt.Errorf("utxo: invalid address %q: %w", addr, err)
	}
	if len(h) != 20 {
		return nil, fmt.Errorf("utxo: invalid address length")
	}
	switch version {
	case c.p.PubKeyHash:
		return &DecodedAddress{Type: P2PKH, Hash: h}, nil
	case c.p.ScriptHash:
		return &DecodedAddress{Type: "p2sh", Hash: h}, nil
	}
	return nil, fmt.Errorf("utxo: address %q has version 0x%02x, not a %s address", addr, version, c.p.Name)
}

func (c *Chain) ValidateAddress(addr string) error {
	_, err := c.DecodeAddress(addr)
	return err
}
