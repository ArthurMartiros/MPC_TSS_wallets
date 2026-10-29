package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"thresholdvault/internal/chain"
)

func TestTransactionLifecycle(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.CreateWallet(ctx, &Wallet{ID: "w", Name: "n", PublicKey: "02", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	tx := &Transaction{
		ID: "tx_1", WalletID: "w", Chain: "ethereum-sepolia", Asset: "ETH", From: "0xa", To: "0xb", Amount: "10",
		Summary:    &chain.Summary{Chain: "ethereum-sepolia", AmountDisplay: "0.00000000000000001 ETH", Sighash: "ab"},
		UnsignedTx: "02f8", Sighash: "ab", Status: TxPrepared, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.CreateTransaction(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateTransaction(ctx, &Transaction{ID: "tx_bad", WalletID: "missing", Summary: &chain.Summary{}, CreatedAt: now, UpdatedAt: now}); err == nil {
		t.Fatal("transaction for unknown wallet accepted (foreign key)")
	}

	tx.Status, tx.Approval = TxApproved, "token"
	if err := s.UpdateTransaction(ctx, tx, TxPrepared); err != nil {
		t.Fatal(err)
	}
	// A second update expecting the old status loses the race.
	if err := s.UpdateTransaction(ctx, tx, TxPrepared); !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	tx.Status, tx.Signers, tx.TxHash = TxSigned, []string{"user", "server"}, "0xhash"
	if err := s.UpdateTransaction(ctx, tx, TxApproved); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetTransaction(ctx, "tx_1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != TxSigned || got.Approval != "token" || len(got.Signers) != 2 || got.Summary.Sighash != "ab" || !got.CreatedAt.Equal(now) {
		t.Fatalf("got %+v", got)
	}
	list, err := s.ListTransactions(ctx, "w")
	if err != nil || len(list) != 1 {
		t.Fatalf("list %v %v", list, err)
	}
	if list, _ := s.ListTransactions(ctx, "other"); len(list) != 0 {
		t.Fatalf("filter by wallet: %v", list)
	}
	if _, err := s.GetTransaction(ctx, "tx_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}
