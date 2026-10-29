package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestWalletRoundTripAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	w := &Wallet{
		ID: "w_1", Name: "treasury", PublicKey: "02abc", CreatedAt: time.Now().Truncate(time.Millisecond),
		Addresses: []Address{{Chain: "ethereum-sepolia", Address: "0xabc"}, {Chain: "bitcoin-testnet", Address: "tb1q"}},
	}
	if err := s.CreateWallet(ctx, w); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateWallet(ctx, w); err == nil {
		t.Fatal("duplicate wallet accepted")
	}
	s.Close()

	// Reopen: data persists and migrations are idempotent.
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.GetWallet(ctx, "w_1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "treasury" || !got.CreatedAt.Equal(w.CreatedAt) || len(got.Addresses) != 2 {
		t.Fatalf("got %+v", got)
	}
	if a, ok := got.AddressFor("ethereum-sepolia"); !ok || a != "0xabc" {
		t.Fatalf("AddressFor = %q %v", a, ok)
	}
	list, err := s.ListWallets(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}
	if _, err := s.GetWallet(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestCreateWalletIsAtomic(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	// Duplicate (wallet, chain) violates the primary key mid-transaction.
	w := &Wallet{ID: "w", Name: "n", PublicKey: "02", CreatedAt: time.Now(),
		Addresses: []Address{{Chain: "c", Address: "a"}, {Chain: "c", Address: "b"}}}
	if err := s.CreateWallet(ctx, w); err == nil {
		t.Fatal("expected error")
	}
	if _, err := s.GetWallet(ctx, "w"); !errors.Is(err, ErrNotFound) {
		t.Fatal("partial wallet was committed")
	}
}
