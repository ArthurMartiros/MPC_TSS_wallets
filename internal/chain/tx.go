package chain

import (
	"context"
	"errors"
	"math/big"
)

// ErrInsufficientFunds is returned (wrapped) when a wallet can't cover a
// transfer plus fees.
var ErrInsufficientFunds = errors.New("insufficient funds")

// Summary is a chain-independent, human-checkable description of an
// unsigned transaction, produced by decoding the raw bytes. Signers build
// their own Summary from the raw transaction rather than trusting one sent
// by the coordinator.
type Summary struct {
	Chain         string `json:"chain"`
	Asset         string `json:"asset"`
	Contract      string `json:"contract,omitempty"` // token contract, if any
	To            string `json:"to"`                 // final recipient (not the token contract)
	Amount        string `json:"amount"`             // base units
	AmountDisplay string `json:"amount_display"`     // e.g. "0.01 ETH"
	MaxFee        string `json:"max_fee"`            // base units of the native coin
	MaxFeeDisplay string `json:"max_fee_display"`
	Nonce         uint64 `json:"nonce"`
	Sighash       string `json:"sighash"` // hex digest the signers sign
}

// TxCodec is the offline transaction logic of a chain: no network access, so
// signers can run it to verify what they are asked to sign.
type TxCodec interface {
	// DecodeUnsigned parses and validates an unsigned transaction.
	DecodeUnsigned(raw []byte) (*Summary, error)
	// ApplySignature attaches a 65-byte r||s||v signature, checks that it
	// recovers to the wallet address `from`, and returns the signed
	// transaction and its hash.
	ApplySignature(raw, sig65 []byte, from string) (signed []byte, txHash string, err error)
}

// TxStatus is the on-chain state of a broadcast transaction.
type TxStatus string

const (
	TxPending   TxStatus = "pending"
	TxConfirmed TxStatus = "confirmed"
	TxFailed    TxStatus = "failed"
)

// Receipt is the result of looking up a broadcast transaction.
type Receipt struct {
	Status      TxStatus `json:"status"`
	BlockNumber uint64   `json:"block_number,omitempty"`
}

// Node is live network access for a chain (via an RPC endpoint).
type Node interface {
	Balance(ctx context.Context, address string, asset Asset) (*big.Int, error)
	// BuildTransfer returns an unsigned transaction moving amount (base
	// units) of asset from `from` to `to`, with nonce and fees filled in.
	BuildTransfer(ctx context.Context, from, to string, asset Asset, amount *big.Int) ([]byte, error)
	Broadcast(ctx context.Context, signed []byte) (txHash string, err error)
	Receipt(ctx context.Context, txHash string) (*Receipt, error)
	ExplorerURL(txHash string) string
}
