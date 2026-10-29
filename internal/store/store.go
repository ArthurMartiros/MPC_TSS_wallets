// Package store persists the coordinator's metadata in SQLite: wallets,
// their public keys and addresses, and (later) transactions. It never
// contains key shares.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

var ErrNotFound = errors.New("store: not found")

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// migrations are applied in order; their index+1 is the schema version.
var migrations = []string{
	`CREATE TABLE wallets (
		id         TEXT PRIMARY KEY,
		name       TEXT NOT NULL,
		public_key TEXT NOT NULL UNIQUE,
		created_at TEXT NOT NULL
	);
	CREATE TABLE addresses (
		wallet_id TEXT NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
		chain     TEXT NOT NULL,
		address   TEXT NOT NULL,
		PRIMARY KEY (wallet_id, chain)
	);`,
	`CREATE TABLE transactions (
		id           TEXT PRIMARY KEY,
		wallet_id    TEXT NOT NULL REFERENCES wallets(id),
		chain        TEXT NOT NULL,
		asset        TEXT NOT NULL,
		from_address TEXT NOT NULL,
		to_address   TEXT NOT NULL,
		amount       TEXT NOT NULL,
		summary      TEXT NOT NULL,
		unsigned_tx  TEXT NOT NULL,
		sighash      TEXT NOT NULL,
		status       TEXT NOT NULL,
		approval     TEXT NOT NULL DEFAULT '',
		signers      TEXT NOT NULL DEFAULT '',
		signature    TEXT NOT NULL DEFAULT '',
		signed_tx    TEXT NOT NULL DEFAULT '',
		tx_hash      TEXT NOT NULL DEFAULT '',
		block_number INTEGER NOT NULL DEFAULT 0,
		error        TEXT NOT NULL DEFAULT '',
		created_at   TEXT NOT NULL,
		updated_at   TEXT NOT NULL
	);
	CREATE INDEX transactions_by_wallet ON transactions (wallet_id, created_at);`,
}

// Open opens (creating if needed) the database at path and migrates it.
// Use ":memory:" for tests.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection keeps SQLite simple and makes ":memory:" work.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return err
	}
	var version int
	err := s.db.QueryRowContext(ctx, `SELECT version FROM schema_version`).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := s.db.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (0)`); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	for i := version; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE schema_version SET version = ?`, i+1); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Address is a wallet's address on one chain.
type Address struct {
	Chain   string `json:"chain"`
	Address string `json:"address"`
}

// Wallet is a threshold wallet as the coordinator sees it: public data only.
type Wallet struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	PublicKey string    `json:"public_key"` // compressed secp256k1, hex
	CreatedAt time.Time `json:"created_at"`
	Addresses []Address `json:"addresses"`
}

// AddressFor returns the wallet's address on chain, if any.
func (w *Wallet) AddressFor(chain string) (string, bool) {
	for _, a := range w.Addresses {
		if a.Chain == chain {
			return a.Address, true
		}
	}
	return "", false
}

// CreateWallet inserts a wallet with its addresses atomically.
func (s *Store) CreateWallet(ctx context.Context, w *Wallet) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO wallets (id, name, public_key, created_at) VALUES (?, ?, ?, ?)`,
		w.ID, w.Name, w.PublicKey, w.CreatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("store: insert wallet: %w", err)
	}
	for _, a := range w.Addresses {
		if _, err := tx.ExecContext(ctx, `INSERT INTO addresses (wallet_id, chain, address) VALUES (?, ?, ?)`,
			w.ID, a.Chain, a.Address); err != nil {
			return fmt.Errorf("store: insert address: %w", err)
		}
	}
	return tx.Commit()
}

// GetWallet loads one wallet with its addresses.
func (s *Store) GetWallet(ctx context.Context, id string) (*Wallet, error) {
	w := &Wallet{}
	var created string
	err := s.db.QueryRowContext(ctx, `SELECT id, name, public_key, created_at FROM wallets WHERE id = ?`, id).
		Scan(&w.ID, &w.Name, &w.PublicKey, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: wallet %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, err
	}
	if w.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return nil, err
	}
	if w.Addresses, err = s.addresses(ctx, id); err != nil {
		return nil, err
	}
	return w, nil
}

// ListWallets returns all wallets, oldest first.
func (s *Store) ListWallets(ctx context.Context) ([]*Wallet, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM wallets ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]*Wallet, 0, len(ids))
	for _, id := range ids {
		w, err := s.GetWallet(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, nil
}

func (s *Store) addresses(ctx context.Context, walletID string) ([]Address, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT chain, address FROM addresses WHERE wallet_id = ? ORDER BY chain`, walletID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Address{}
	for rows.Next() {
		var a Address
		if err := rows.Scan(&a.Chain, &a.Address); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
