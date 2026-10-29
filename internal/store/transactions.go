package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"thresholdvault/internal/chain"
)

// ErrConflict means the transaction was not in the expected status, e.g. a
// second concurrent "sign" call.
var ErrConflict = errors.New("store: transaction status changed concurrently")

// TxStatus is the lifecycle state of a transaction.
type TxStatus string

const (
	TxPrepared  TxStatus = "prepared"  // unsigned tx built, awaiting user approval
	TxApproved  TxStatus = "approved"  // user approval recorded
	TxSigning   TxStatus = "signing"   // threshold signing in progress
	TxSigned    TxStatus = "signed"    // signed, not yet broadcast
	TxBroadcast TxStatus = "broadcast" // submitted to the network
	TxConfirmed TxStatus = "confirmed" // mined successfully
	TxFailed    TxStatus = "failed"    // mined but reverted
)

// Transaction is the coordinator's record of one transfer.
type Transaction struct {
	ID          string         `json:"id"`
	WalletID    string         `json:"wallet_id"`
	Chain       string         `json:"chain"`
	Asset       string         `json:"asset"`
	From        string         `json:"from"`
	To          string         `json:"to"`
	Amount      string         `json:"amount"` // base units
	Summary     *chain.Summary `json:"summary"`
	UnsignedTx  string         `json:"unsigned_tx"` // hex
	Sighash     string         `json:"sighash"`     // hex
	Status      TxStatus       `json:"status"`
	Approval    string         `json:"approval,omitempty"`
	Signers     []string       `json:"signers,omitempty"`
	Signature   string         `json:"signature,omitempty"` // hex r||s||v
	SignedTx    string         `json:"signed_tx,omitempty"` // hex
	TxHash      string         `json:"tx_hash,omitempty"`
	BlockNumber uint64         `json:"block_number,omitempty"`
	Error       string         `json:"error,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	// ExplorerURL is computed, not stored.
	ExplorerURL string `json:"explorer_url,omitempty"`
}

const txColumns = `id, wallet_id, chain, asset, from_address, to_address, amount, summary, unsigned_tx, sighash,
	status, approval, signers, signature, signed_tx, tx_hash, block_number, error, created_at, updated_at`

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// CreateTransaction inserts a new transaction.
func (s *Store) CreateTransaction(ctx context.Context, tx *Transaction) error {
	summary, err := json.Marshal(tx.Summary)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO transactions (`+txColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		tx.ID, tx.WalletID, tx.Chain, tx.Asset, tx.From, tx.To, tx.Amount, string(summary), tx.UnsignedTx, tx.Sighash,
		tx.Status, tx.Approval, strings.Join(tx.Signers, ","), tx.Signature, tx.SignedTx, tx.TxHash, tx.BlockNumber, tx.Error,
		ts(tx.CreatedAt), ts(tx.UpdatedAt))
	if err != nil {
		return fmt.Errorf("store: insert transaction: %w", err)
	}
	return nil
}

// UpdateTransaction writes the mutable fields of tx, but only if the stored
// status is still `from`. On success tx.UpdatedAt is refreshed.
func (s *Store) UpdateTransaction(ctx context.Context, tx *Transaction, from TxStatus) error {
	tx.UpdatedAt = time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `UPDATE transactions SET status=?, approval=?, signers=?, signature=?, signed_tx=?,
		tx_hash=?, block_number=?, error=?, updated_at=? WHERE id=? AND status=?`,
		tx.Status, tx.Approval, strings.Join(tx.Signers, ","), tx.Signature, tx.SignedTx,
		tx.TxHash, tx.BlockNumber, tx.Error, ts(tx.UpdatedAt), tx.ID, from)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return fmt.Errorf("%w: %s is no longer %s", ErrConflict, tx.ID, from)
	}
	return nil
}

func scanTx(row interface{ Scan(...any) error }) (*Transaction, error) {
	var (
		tx                         Transaction
		summary, signers, cat, uat string
	)
	err := row.Scan(&tx.ID, &tx.WalletID, &tx.Chain, &tx.Asset, &tx.From, &tx.To, &tx.Amount, &summary, &tx.UnsignedTx, &tx.Sighash,
		&tx.Status, &tx.Approval, &signers, &tx.Signature, &tx.SignedTx, &tx.TxHash, &tx.BlockNumber, &tx.Error, &cat, &uat)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(summary), &tx.Summary); err != nil {
		return nil, err
	}
	if signers != "" {
		tx.Signers = strings.Split(signers, ",")
	}
	if tx.CreatedAt, err = time.Parse(time.RFC3339Nano, cat); err != nil {
		return nil, err
	}
	if tx.UpdatedAt, err = time.Parse(time.RFC3339Nano, uat); err != nil {
		return nil, err
	}
	return &tx, nil
}

// GetTransaction loads one transaction.
func (s *Store) GetTransaction(ctx context.Context, id string) (*Transaction, error) {
	tx, err := scanTx(s.db.QueryRowContext(ctx, `SELECT `+txColumns+` FROM transactions WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: transaction %s", ErrNotFound, id)
	}
	return tx, err
}

// ListTransactions returns transactions, newest first, optionally filtered
// by wallet.
func (s *Store) ListTransactions(ctx context.Context, walletID string) ([]*Transaction, error) {
	q := `SELECT ` + txColumns + ` FROM transactions`
	var args []any
	if walletID != "" {
		q += ` WHERE wallet_id = ?`
		args = append(args, walletID)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY created_at DESC, id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Transaction{}
	for rows.Next() {
		tx, err := scanTx(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, tx)
	}
	return out, rows.Err()
}
