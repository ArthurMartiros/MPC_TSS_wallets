package coordinator

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"thresholdvault/internal/approval"
	"thresholdvault/internal/chain"
	"thresholdvault/internal/identity"
	"thresholdvault/internal/mpc"
	"thresholdvault/internal/signer"
	"thresholdvault/internal/store"
)

var (
	// ErrUnsupported means the chain has no live network access configured.
	ErrUnsupported = errors.New("not supported")
	// ErrState means the transaction is not in a status that allows the action.
	ErrState = errors.New("invalid transaction state")
	// ErrUpstream means the blockchain node failed or rejected a request.
	ErrUpstream = errors.New("blockchain node error")
)

// upstream classifies a node error: insufficient funds is the caller's
// problem, anything else is the node's.
func upstream(err error) error {
	if errors.Is(err, chain.ErrInsufficientFunds) {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return fmt.Errorf("%w: %v", ErrUpstream, err)
}

// routineSigners co-sign everyday transactions. The backup share is kept
// for recovery (backup + user or backup + server).
var routineSigners = []string{mpc.PartyUser, mpc.PartyServer}

func (c *Coordinator) node(chainID string) (chain.Node, error) {
	n, ok := c.nodes[chainID]
	if !ok {
		return nil, fmt.Errorf("%w: no RPC endpoint configured for %s", ErrUnsupported, chainID)
	}
	return n, nil
}

func (c *Coordinator) codec(chainID string) (chain.Chain, chain.TxCodec, error) {
	ch, err := c.chains.Get(chainID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	codec, ok := ch.(chain.TxCodec)
	if !ok {
		return nil, nil, fmt.Errorf("%w: transactions on %s", ErrUnsupported, chainID)
	}
	return ch, codec, nil
}

func (c *Coordinator) withExplorer(tx *store.Transaction) *store.Transaction {
	if n, ok := c.nodes[tx.Chain]; ok && tx.TxHash != "" {
		tx.ExplorerURL = n.ExplorerURL(tx.TxHash)
	}
	return tx
}

// BalanceResult is a wallet balance on one chain.
type BalanceResult struct {
	WalletID       string `json:"wallet_id"`
	Chain          string `json:"chain"`
	Asset          string `json:"asset"`
	Address        string `json:"address"`
	Balance        string `json:"balance"` // base units
	BalanceDisplay string `json:"balance_display"`
	Decimals       uint8  `json:"decimals"`
}

// Balance queries a wallet's balance of asset (native coin if empty).
func (c *Coordinator) Balance(ctx context.Context, walletID, chainID, assetSymbol string) (*BalanceResult, error) {
	w, err := c.store.GetWallet(ctx, walletID)
	if err != nil {
		return nil, err
	}
	ch, err := c.chains.Get(chainID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	asset, err := pickAsset(ch, assetSymbol)
	if err != nil {
		return nil, err
	}
	n, err := c.node(chainID)
	if err != nil {
		return nil, err
	}
	addr, ok := w.AddressFor(chainID)
	if !ok {
		return nil, fmt.Errorf("%w: wallet has no %s address", ErrInvalid, chainID)
	}
	bal, err := n.Balance(ctx, addr, asset)
	if err != nil {
		return nil, upstream(err)
	}
	return &BalanceResult{
		WalletID: walletID, Chain: chainID, Asset: asset.Symbol, Address: addr, Decimals: asset.Decimals,
		Balance: bal.String(), BalanceDisplay: chain.FormatAmount(bal, asset.Decimals) + " " + asset.Symbol,
	}, nil
}

func pickAsset(ch chain.Chain, symbol string) (chain.Asset, error) {
	if symbol == "" {
		return ch.Assets()[0], nil
	}
	a, err := chain.FindAsset(ch, strings.ToUpper(symbol))
	if err != nil {
		return chain.Asset{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return a, nil
}

// PrepareRequest describes a transfer to build.
type PrepareRequest struct {
	WalletID string `json:"wallet_id"`
	Chain    string `json:"chain"`
	Asset    string `json:"asset"`  // symbol; empty = native coin
	To       string `json:"to"`     // recipient address
	Amount   string `json:"amount"` // decimal, e.g. "0.01"
}

// PrepareTransaction builds an unsigned transaction with live nonce and fees
// and records it as "prepared". Nothing is signed yet.
func (c *Coordinator) PrepareTransaction(ctx context.Context, req PrepareRequest) (*store.Transaction, error) {
	w, err := c.store.GetWallet(ctx, req.WalletID)
	if err != nil {
		return nil, err
	}
	ch, codec, err := c.codec(req.Chain)
	if err != nil {
		return nil, err
	}
	n, err := c.node(req.Chain)
	if err != nil {
		return nil, err
	}
	asset, err := pickAsset(ch, req.Asset)
	if err != nil {
		return nil, err
	}
	if err := ch.ValidateAddress(req.To); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	amount, err := chain.ParseAmount(req.Amount, asset.Decimals)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	from, ok := w.AddressFor(req.Chain)
	if !ok {
		return nil, fmt.Errorf("%w: wallet has no %s address", ErrInvalid, req.Chain)
	}

	raw, err := n.BuildTransfer(ctx, from, req.To, asset, amount)
	if err != nil {
		return nil, upstream(err)
	}
	summary, err := codec.DecodeUnsigned(raw)
	if err != nil {
		return nil, fmt.Errorf("built transaction failed self-check: %w", err)
	}
	if !strings.EqualFold(summary.To, req.To) || summary.Amount != amount.String() || summary.Asset != asset.Symbol {
		return nil, errors.New("built transaction does not match the request")
	}
	now := time.Now().UTC()
	tx := &store.Transaction{
		ID: newID("tx"), WalletID: w.ID, Chain: req.Chain, Asset: asset.Symbol, From: from, To: summary.To,
		Amount: amount.String(), Summary: summary, UnsignedTx: hex.EncodeToString(raw), Sighash: summary.Sighash,
		Status: store.TxPrepared, CreatedAt: now, UpdatedAt: now,
	}
	if err := c.store.CreateTransaction(ctx, tx); err != nil {
		return nil, err
	}
	c.log.Info("transaction prepared", "tx", tx.ID, "chain", tx.Chain, "to", tx.To, "amount", summary.AmountDisplay)
	return tx, nil
}

// userIdentity fetches the user signer's public identity for approval
// checks. Signers verify approvals against their own pinned copy; this check
// only lets the coordinator reject bad approvals early.
func (c *Coordinator) userIdentity(ctx context.Context) (*identity.Public, error) {
	res, err := c.signers[mpc.PartyUser].Identity(ctx)
	if err != nil {
		return nil, err
	}
	return identity.ParsePublic(res.Identity)
}

// ApproveTransaction records the user's approval token, produced by the
// user signer after it independently decoded and the user confirmed the
// transaction.
func (c *Coordinator) ApproveTransaction(ctx context.Context, id, token string) (*store.Transaction, error) {
	tx, err := c.store.GetTransaction(ctx, id)
	if err != nil {
		return nil, err
	}
	if tx.Status != store.TxPrepared && tx.Status != store.TxApproved {
		return nil, fmt.Errorf("%w: transaction is %s", ErrState, tx.Status)
	}
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("%w: approval token is required (obtain it from the user signer's review/confirm API)", ErrInvalid)
	}
	pub, err := c.userIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := approval.Verify(token, pub, approval.Claims{
		TxID: tx.ID, WalletID: tx.WalletID, Chain: tx.Chain, Sighash: tx.Sighash,
	}, time.Now()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	from := tx.Status
	tx.Status, tx.Approval, tx.Error = store.TxApproved, token, ""
	if err := c.store.UpdateTransaction(ctx, tx, from); err != nil {
		return nil, err
	}
	c.log.Info("transaction approved", "tx", tx.ID)
	return tx, nil
}

// SignTransaction runs threshold signing with the user and server signers.
// Each signer independently re-checks the transaction and the approval.
func (c *Coordinator) SignTransaction(ctx context.Context, id string) (*store.Transaction, error) {
	tx, err := c.store.GetTransaction(ctx, id)
	if err != nil {
		return nil, err
	}
	if tx.Status != store.TxApproved {
		return nil, fmt.Errorf("%w: transaction is %s; it must be approved first", ErrState, tx.Status)
	}
	_, codec, err := c.codec(tx.Chain)
	if err != nil {
		return nil, err
	}
	// Claim the transaction so concurrent sign calls don't race.
	tx.Status = store.TxSigning
	if err := c.store.UpdateTransaction(ctx, tx, store.TxApproved); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrState, err)
	}
	fail := func(err error) (*store.Transaction, error) {
		tx.Status, tx.Error = store.TxApproved, err.Error()
		if uerr := c.store.UpdateTransaction(context.WithoutCancel(ctx), tx, store.TxSigning); uerr != nil {
			c.log.Error("reset transaction after failed signing", "tx", tx.ID, "err", uerr)
		}
		return nil, err
	}

	req := signer.SignRequest{
		SessionID: newID("sg"), WalletID: tx.WalletID, Signers: routineSigners, Digest: tx.Sighash,
		Chain: tx.Chain, Transaction: tx.UnsignedTx, TxID: tx.ID, Approval: tx.Approval,
	}
	c.log.Info("threshold signing", "tx", tx.ID, "signers", routineSigners)
	results, err := c.fanOut(ctx, routineSigners, func(ctx context.Context, s SignerAPI) (any, error) {
		return s.Sign(ctx, req)
	})
	if err != nil {
		return fail(fmt.Errorf("signing failed: %w", err))
	}
	sig := results[mpc.PartyUser].(*signer.SignResult).Signature
	if other := results[mpc.PartyServer].(*signer.SignResult).Signature; other != sig {
		return fail(errors.New("signers returned different signatures"))
	}
	raw, err := hex.DecodeString(tx.UnsignedTx)
	if err != nil {
		return fail(err)
	}
	signed, hash, err := codec.ApplySignature(raw, sig.Bytes(), tx.From)
	if err != nil {
		return fail(err)
	}
	tx.Status, tx.Signers, tx.Error = store.TxSigned, routineSigners, ""
	tx.Signature, tx.SignedTx, tx.TxHash = hex.EncodeToString(sig.Bytes()), hex.EncodeToString(signed), hash
	if err := c.store.UpdateTransaction(ctx, tx, store.TxSigning); err != nil {
		return nil, err
	}
	c.log.Info("transaction signed", "tx", tx.ID, "hash", hash)
	return c.withExplorer(tx), nil
}

// BroadcastTransaction submits a signed transaction. Re-broadcasting an
// already broadcast transaction is allowed (idempotent).
func (c *Coordinator) BroadcastTransaction(ctx context.Context, id string) (*store.Transaction, error) {
	tx, err := c.store.GetTransaction(ctx, id)
	if err != nil {
		return nil, err
	}
	if tx.Status != store.TxSigned && tx.Status != store.TxBroadcast {
		return nil, fmt.Errorf("%w: transaction is %s; it must be signed first", ErrState, tx.Status)
	}
	n, err := c.node(tx.Chain)
	if err != nil {
		return nil, err
	}
	signed, err := hex.DecodeString(tx.SignedTx)
	if err != nil {
		return nil, err
	}
	hash, err := n.Broadcast(ctx, signed)
	if err != nil {
		return nil, upstream(err)
	}
	if !strings.EqualFold(hash, tx.TxHash) {
		return nil, fmt.Errorf("node reported hash %s, expected %s", hash, tx.TxHash)
	}
	if tx.Status == store.TxSigned {
		tx.Status = store.TxBroadcast
		if err := c.store.UpdateTransaction(ctx, tx, store.TxSigned); err != nil {
			return nil, err
		}
	}
	c.log.Info("transaction broadcast", "tx", tx.ID, "hash", hash)
	return c.withExplorer(tx), nil
}

// Transaction returns a transaction, refreshing its on-chain status if it
// has been broadcast.
func (c *Coordinator) Transaction(ctx context.Context, id string) (*store.Transaction, error) {
	tx, err := c.store.GetTransaction(ctx, id)
	if err != nil {
		return nil, err
	}
	if tx.Status == store.TxBroadcast {
		if n, ok := c.nodes[tx.Chain]; ok {
			if r, err := n.Receipt(ctx, tx.TxHash); err == nil && r.Status != chain.TxPending {
				tx.Status, tx.BlockNumber = store.TxConfirmed, r.BlockNumber
				if r.Status == chain.TxFailed {
					tx.Status = store.TxFailed
				}
				if err := c.store.UpdateTransaction(ctx, tx, store.TxBroadcast); err != nil && !errors.Is(err, store.ErrConflict) {
					return nil, err
				}
			}
		}
	}
	return c.withExplorer(tx), nil
}

// Transactions lists transactions, optionally for one wallet.
func (c *Coordinator) Transactions(ctx context.Context, walletID string) ([]*store.Transaction, error) {
	txs, err := c.store.ListTransactions(ctx, walletID)
	if err != nil {
		return nil, err
	}
	for _, tx := range txs {
		c.withExplorer(tx)
	}
	return txs, nil
}
