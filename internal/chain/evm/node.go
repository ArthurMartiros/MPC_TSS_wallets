package evm

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	"thresholdvault/internal/chain"
)

// RPC is the subset of go-ethereum's ethclient used here. Both
// *ethclient.Client and the in-memory simulated backend implement it.
type RPC interface {
	ChainID(ctx context.Context) (*big.Int, error)
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
	SuggestGasTipCap(ctx context.Context) (*big.Int, error)
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
	EstimateGas(ctx context.Context, call ethereum.CallMsg) (uint64, error)
	BalanceAt(ctx context.Context, account common.Address, block *big.Int) (*big.Int, error)
	CallContract(ctx context.Context, call ethereum.CallMsg, block *big.Int) ([]byte, error)
	SendTransaction(ctx context.Context, tx *types.Transaction) error
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
}

// Node is a chain.Node for an EVM network.
type Node struct {
	chain *Chain
	rpc   RPC

	mu       sync.Mutex
	verified bool // RPC chain id matched the configuration
}

var _ chain.Node = (*Node)(nil)

// Dial connects to a JSON-RPC endpoint.
func Dial(ctx context.Context, c *Chain, url string) (*Node, error) {
	client, err := ethclient.DialContext(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("evm: dial %s: %w", c.ID(), err)
	}
	return NewNode(c, client), nil
}

// NewNode wraps an existing RPC client.
func NewNode(c *Chain, rpc RPC) *Node { return &Node{chain: c, rpc: rpc} }

// checkChainID verifies once that the RPC serves the configured chain, so a
// misconfigured URL can't make us build transactions for another network.
func (n *Node) checkChainID(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.verified {
		return nil
	}
	id, err := n.rpc.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("evm: %s chain id: %w", n.chain.ID(), err) // transient: retried next call
	}
	if id.Cmp(n.chain.cfg.ChainID) != 0 {
		return fmt.Errorf("evm: RPC for %s serves chain id %s, expected %s", n.chain.ID(), id, n.chain.cfg.ChainID)
	}
	n.verified = true
	return nil
}

// Balance returns the native or token balance of address in base units.
func (n *Node) Balance(ctx context.Context, address string, asset chain.Asset) (*big.Int, error) {
	if err := n.checkChainID(ctx); err != nil {
		return nil, err
	}
	addr, err := ParseAddress(address)
	if err != nil {
		return nil, err
	}
	if asset.IsNative() {
		return n.rpc.BalanceAt(ctx, addr, nil)
	}
	contract, err := ParseAddress(asset.Contract)
	if err != nil {
		return nil, err
	}
	out, err := n.rpc.CallContract(ctx, ethereum.CallMsg{To: &contract, Data: append(append([]byte{}, selectorBalanceOf...), common.LeftPadBytes(addr.Bytes(), 32)...)}, nil)
	if err != nil {
		return nil, fmt.Errorf("evm: %s balanceOf: %w", asset.Symbol, err)
	}
	if len(out) != 32 {
		return nil, fmt.Errorf("evm: %s balanceOf returned %d bytes", asset.Symbol, len(out))
	}
	return new(big.Int).SetBytes(out), nil
}

// BuildTransfer fills nonce, gas and EIP-1559 fees from the network and
// checks the wallet can afford amount + maximum fee.
func (n *Node) BuildTransfer(ctx context.Context, from, to string, asset chain.Asset, amount *big.Int) ([]byte, error) {
	if err := n.checkChainID(ctx); err != nil {
		return nil, err
	}
	fromAddr, err := ParseAddress(from)
	if err != nil {
		return nil, err
	}
	toAddr, err := ParseAddress(to)
	if err != nil {
		return nil, err
	}
	if amount == nil || amount.Sign() <= 0 {
		return nil, errors.New("evm: amount must be positive")
	}
	nonce, err := n.rpc.PendingNonceAt(ctx, fromAddr)
	if err != nil {
		return nil, fmt.Errorf("evm: nonce: %w", err)
	}
	tip, err := n.rpc.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, fmt.Errorf("evm: gas tip: %w", err)
	}
	head, err := n.rpc.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("evm: latest header: %w", err)
	}
	if head.BaseFee == nil {
		return nil, errors.New("evm: network has no EIP-1559 base fee")
	}
	// Max fee = 2 × base fee + tip: survives several full blocks of base
	// fee increases; unused fee is not charged.
	feeCap := new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), tip)

	// Check balances before gas estimation, which would otherwise fail with
	// a less readable node error.
	nat := n.chain.cfg.Native
	native, err := n.rpc.BalanceAt(ctx, fromAddr, nil)
	if err != nil {
		return nil, fmt.Errorf("evm: balance: %w", err)
	}
	insufficient := func(sym string, have, need *big.Int, dec uint8, what string) error {
		return fmt.Errorf("evm: %w: %s%s: have %s, need %s", chain.ErrInsufficientFunds, sym, what,
			chain.FormatAmount(have, dec), chain.FormatAmount(need, dec))
	}
	if asset.IsNative() {
		if native.Cmp(amount) < 0 {
			return nil, insufficient(nat.Symbol, native, amount, nat.Decimals, "")
		}
	} else {
		tokenBal, err := n.Balance(ctx, from, asset)
		if err != nil {
			return nil, err
		}
		if tokenBal.Cmp(amount) < 0 {
			return nil, insufficient(asset.Symbol, tokenBal, amount, asset.Decimals, "")
		}
	}

	// Build once without gas to get the exact call for estimation.
	draft, err := n.chain.NewTransferTx(toAddr, asset, amount, nonce, 1, tip, feeCap)
	if err != nil {
		return nil, err
	}
	gas, err := n.rpc.EstimateGas(ctx, ethereum.CallMsg{From: fromAddr, To: draft.To(), Value: draft.Value(), Data: draft.Data()})
	if err != nil {
		return nil, fmt.Errorf("evm: estimate gas: %w", err)
	}
	if !asset.IsNative() {
		gas = gas * 12 / 10 // token transfers: 20% headroom for state changes
	}

	need := new(big.Int).Mul(new(big.Int).SetUint64(gas), feeCap)
	if asset.IsNative() {
		need.Add(need, amount)
	}
	if native.Cmp(need) < 0 {
		return nil, insufficient(nat.Symbol, native, need, nat.Decimals, " for amount + max fee")
	}

	tx, err := n.chain.NewTransferTx(toAddr, asset, amount, nonce, gas, tip, feeCap)
	if err != nil {
		return nil, err
	}
	return tx.MarshalBinary()
}

// Broadcast submits a signed transaction. Resubmitting one the node already
// has is not an error.
func (n *Node) Broadcast(ctx context.Context, signed []byte) (string, error) {
	if err := n.checkChainID(ctx); err != nil {
		return "", err
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(signed); err != nil {
		return "", fmt.Errorf("evm: decode signed transaction: %w", err)
	}
	if err := n.rpc.SendTransaction(ctx, tx); err != nil && !strings.Contains(strings.ToLower(err.Error()), "already known") {
		return "", fmt.Errorf("evm: broadcast: %w", err)
	}
	return tx.Hash().Hex(), nil
}

// Receipt reports whether a transaction is pending, confirmed or failed.
func (n *Node) Receipt(ctx context.Context, txHash string) (*chain.Receipt, error) {
	r, err := n.rpc.TransactionReceipt(ctx, common.HexToHash(txHash))
	// geth answers "transaction indexing is in progress" instead of NotFound
	// while its tx index is still being built; both mean "not mined yet".
	if errors.Is(err, ethereum.NotFound) || (err != nil && strings.Contains(err.Error(), "indexing is in progress")) {
		return &chain.Receipt{Status: chain.TxPending}, nil
	}
	if err != nil {
		return nil, err
	}
	out := &chain.Receipt{Status: chain.TxConfirmed, BlockNumber: r.BlockNumber.Uint64()}
	if r.Status != types.ReceiptStatusSuccessful {
		out.Status = chain.TxFailed
	}
	return out, nil
}

// ExplorerURL links to the transaction on the chain's block explorer.
func (n *Node) ExplorerURL(txHash string) string {
	if n.chain.cfg.ExplorerTx == "" {
		return ""
	}
	return fmt.Sprintf(n.chain.cfg.ExplorerTx, txHash)
}
