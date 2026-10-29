// Package coordinator orchestrates wallets and transactions. It drives the
// signers (keygen, signing) and the chain adapters, and persists public
// metadata. It holds no key material and cannot sign on its own.
package coordinator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"thresholdvault/internal/chain"
	"thresholdvault/internal/mpc"
	"thresholdvault/internal/signer"
	"thresholdvault/internal/store"
)

// ErrInvalid marks a request the caller must fix.
var ErrInvalid = errors.New("invalid request")

// SignerAPI is the subset of signer.Client the coordinator uses.
type SignerAPI interface {
	Identity(ctx context.Context) (*signer.IdentityResponse, error)
	Health(ctx context.Context) (*signer.HealthResponse, error)
	Keygen(ctx context.Context, req signer.KeygenRequest) (*signer.KeygenResult, error)
	Sign(ctx context.Context, req signer.SignRequest) (*signer.SignResult, error)
}

// Config configures a Coordinator.
type Config struct {
	Store   *store.Store
	Chains  *chain.Registry
	Signers map[string]SignerAPI // keyed by committee role
	// Nodes gives live network access per chain ID (balances, nonce/fees,
	// broadcast). Chains without a node support addresses only.
	Nodes  map[string]chain.Node
	Logger *slog.Logger
}

// Coordinator is the application service behind the REST API.
type Coordinator struct {
	store   *store.Store
	chains  *chain.Registry
	signers map[string]SignerAPI
	nodes   map[string]chain.Node
	log     *slog.Logger
}

func New(cfg Config) (*Coordinator, error) {
	for _, name := range mpc.DefaultCommittee {
		if cfg.Signers[name] == nil {
			return nil, fmt.Errorf("coordinator: no client for signer %q", name)
		}
	}
	if cfg.Store == nil || cfg.Chains == nil {
		return nil, errors.New("coordinator: store and chains are required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Nodes == nil {
		cfg.Nodes = map[string]chain.Node{}
	}
	return &Coordinator{store: cfg.Store, chains: cfg.Chains, signers: cfg.Signers, nodes: cfg.Nodes, log: cfg.Logger}, nil
}

// Chains exposes the chain registry.
func (c *Coordinator) Chains() *chain.Registry { return c.chains }

func newID(prefix string) string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return prefix + "_" + hex.EncodeToString(b)
}

// CreateWallet runs distributed key generation on all three signers, then
// derives and stores the wallet's address on every configured chain.
func (c *Coordinator) CreateWallet(ctx context.Context, name string) (*store.Wallet, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 64 {
		return nil, fmt.Errorf("%w: wallet name must be 1-64 characters", ErrInvalid)
	}
	walletID := newID("w")
	req := signer.KeygenRequest{SessionID: newID("kg"), WalletID: walletID}
	c.log.Info("starting DKG", "wallet", walletID, "session", req.SessionID)

	results, err := c.fanOut(ctx, mpc.DefaultCommittee, func(ctx context.Context, s SignerAPI) (any, error) {
		return s.Keygen(ctx, req)
	})
	if err != nil {
		// Signers that finished keep an orphaned share for walletID; it is
		// never referenced because the wallet is not recorded.
		return nil, fmt.Errorf("keygen failed: %w", err)
	}
	var pubHex string
	for name, r := range results {
		kr := r.(*signer.KeygenResult)
		if kr.WalletID != walletID || kr.Party != name {
			return nil, fmt.Errorf("signer %s returned a mismatched keygen result", name)
		}
		if pubHex == "" {
			pubHex = kr.PublicKey
		} else if kr.PublicKey != pubHex {
			return nil, fmt.Errorf("signers disagree on the joint public key; wallet discarded")
		}
	}
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, err
	}
	pub, err := ethcrypto.DecompressPubkey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid joint public key: %w", err)
	}

	w := &store.Wallet{ID: walletID, Name: name, PublicKey: pubHex, CreatedAt: time.Now().UTC()}
	for _, ch := range c.chains.All() {
		addr, err := ch.Address(pub)
		if err != nil {
			return nil, fmt.Errorf("%s address: %w", ch.ID(), err)
		}
		w.Addresses = append(w.Addresses, store.Address{Chain: ch.ID(), Address: addr})
	}
	if err := c.store.CreateWallet(ctx, w); err != nil {
		return nil, err
	}
	c.log.Info("wallet created", "wallet", walletID, "public_key", pubHex)
	return w, nil
}

func (c *Coordinator) Wallet(ctx context.Context, id string) (*store.Wallet, error) {
	return c.store.GetWallet(ctx, id)
}

func (c *Coordinator) Wallets(ctx context.Context) ([]*store.Wallet, error) {
	return c.store.ListWallets(ctx)
}

// SignerStatus describes one signer's reachability.
type SignerStatus struct {
	Name           string `json:"name"`
	Reachable      bool   `json:"reachable"`
	Fingerprint    string `json:"fingerprint,omitempty"`
	PreParamsReady int    `json:"preparams_ready"`
	Error          string `json:"error,omitempty"`
}

// SignerStatuses probes every signer.
func (c *Coordinator) SignerStatuses(ctx context.Context) []SignerStatus {
	out := make([]SignerStatus, len(mpc.DefaultCommittee))
	var wg sync.WaitGroup
	for i, name := range mpc.DefaultCommittee {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st := SignerStatus{Name: name}
			ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			h, err := c.signers[name].Health(ctx)
			if err == nil {
				var id *signer.IdentityResponse
				if id, err = c.signers[name].Identity(ctx); err == nil {
					st.Reachable, st.Fingerprint, st.PreParamsReady = true, id.Fingerprint, h.PreParamsReady
				}
			}
			if err != nil {
				st.Error = err.Error()
			}
			out[i] = st
		}()
	}
	wg.Wait()
	return out
}

// fanOut calls fn on each named signer concurrently. The first failure
// cancels the others.
func (c *Coordinator) fanOut(ctx context.Context, names []string, fn func(context.Context, SignerAPI) (any, error)) (map[string]any, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results = map[string]any{}
		errs    []error
	)
	for _, name := range names {
		s, ok := c.signers[name]
		if !ok {
			return nil, fmt.Errorf("%w: unknown signer %q", ErrInvalid, name)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := fn(ctx, s)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if ctx.Err() == nil || len(errs) == 0 {
					errs = append(errs, fmt.Errorf("%s: %w", name, err))
				}
				cancel()
				return
			}
			results[name] = r
		}()
	}
	wg.Wait()
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return results, nil
}
