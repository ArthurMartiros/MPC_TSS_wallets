// Package signer is one MPC signer node: it owns a single key share per
// wallet (encrypted in its own store), takes part in keygen and signing
// sessions over the relay, and decides for itself whether to sign.
package signer

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"sync"
	"time"

	"thresholdvault/internal/chain"
	"thresholdvault/internal/identity"
	"thresholdvault/internal/mpc"
	"thresholdvault/internal/relay"
	"thresholdvault/internal/sharestore"
)

var walletIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

var (
	ErrWalletExists  = errors.New("signer: wallet already exists")
	ErrWalletUnknown = errors.New("signer: unknown wallet")
	ErrSessionReused = errors.New("signer: session id already used")
	ErrBadRequest    = errors.New("signer: bad request")
	ErrNotAuthorized = errors.New("signer: signing not authorized")
)

// Authorizer decides whether this signer may sign a request. It is the hook
// for the user signer's independent transaction check + explicit approval and
// the server signer's policy. Returning an error refuses to sign.
type Authorizer interface {
	Authorize(ctx context.Context, req *SignRequest) error
}

// AuthorizerFunc adapts a function to Authorizer.
type AuthorizerFunc func(ctx context.Context, req *SignRequest) error

func (f AuthorizerFunc) Authorize(ctx context.Context, req *SignRequest) error { return f(ctx, req) }

// Config configures a Signer.
type Config struct {
	Name       string // committee role: user | server | backup
	Store      *sharestore.Store
	RelayURL   string
	Peers      PeerResolver
	Authorizer Authorizer
	// Chains decodes transactions for review (user signer) and policies.
	Chains     *chain.Registry
	Logger     *slog.Logger
	HTTPClient *http.Client
	// SessionTimeout bounds one keygen/sign session.
	SessionTimeout time.Duration
}

// Signer is a running signer node.
type Signer struct {
	cfg   Config
	store *sharestore.Store
	id    *identity.Identity
	log   *slog.Logger

	mu           sync.Mutex
	usedSessions map[string]bool
	reviews      map[string]pendingReview // tx id -> awaiting user confirmation

	poolMu   sync.Mutex
	poolKick chan struct{}
}

const identityRecord = "identity/self"

// New loads this signer's identity from its store, creating one on first run.
func New(cfg Config) (*Signer, error) {
	if !slices.Contains(mpc.DefaultCommittee, cfg.Name) {
		return nil, fmt.Errorf("signer: name must be one of %v", mpc.DefaultCommittee)
	}
	if cfg.Store == nil || cfg.Peers == nil || cfg.Authorizer == nil || cfg.RelayURL == "" {
		return nil, errors.New("signer: store, peers, authorizer and relay URL are required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = 2 * time.Minute
	}
	id, err := loadOrCreateIdentity(cfg.Store, cfg.Name)
	if err != nil {
		return nil, err
	}
	return &Signer{
		cfg:          cfg,
		store:        cfg.Store,
		id:           id,
		log:          cfg.Logger.With("signer", cfg.Name),
		usedSessions: map[string]bool{},
		reviews:      map[string]pendingReview{},
		poolKick:     make(chan struct{}, 1),
	}, nil
}

func loadOrCreateIdentity(store *sharestore.Store, name string) (*identity.Identity, error) {
	raw, err := store.Get(identityRecord)
	if err == nil {
		id, err := identity.UnmarshalPrivate(raw)
		if err != nil {
			return nil, err
		}
		if id.Name != name {
			return nil, fmt.Errorf("signer: store belongs to %q, not %q", id.Name, name)
		}
		return id, nil
	}
	if !errors.Is(err, sharestore.ErrNotFound) {
		return nil, err
	}
	id, err := identity.Generate(name)
	if err != nil {
		return nil, err
	}
	raw, err = id.MarshalPrivate()
	if err != nil {
		return nil, err
	}
	if err := store.Put(identityRecord, raw); err != nil {
		return nil, err
	}
	return id, nil
}

// Identity returns this signer's public identity.
func (s *Signer) Identity() *identity.Public { return &s.id.Public }

// Name returns this signer's committee role.
func (s *Signer) Name() string { return s.cfg.Name }

// KeygenRequest asks the signer to join a DKG session for a new wallet.
type KeygenRequest struct {
	SessionID string `json:"session_id"`
	WalletID  string `json:"wallet_id"`
}

// KeygenResult is what a signer reports after DKG. It contains only public
// data; the share stays in the signer's store.
type KeygenResult struct {
	WalletID  string `json:"wallet_id"`
	Party     string `json:"party"`
	PublicKey string `json:"public_key"` // compressed secp256k1, hex
}

// SignRequest asks the signer to join a threshold signing session.
type SignRequest struct {
	SessionID string   `json:"session_id"`
	WalletID  string   `json:"wallet_id"`
	Signers   []string `json:"signers"`
	// Digest is the 32-byte hash to sign, hex. Authorizers must not trust
	// it blindly: they recompute it from Transaction.
	Digest string `json:"digest"`
	// Chain and Transaction carry the unsigned transaction so authorizers
	// can decode and check it independently of the coordinator.
	Chain       string `json:"chain,omitempty"`
	Transaction string `json:"transaction,omitempty"` // hex-encoded unsigned tx
	// TxID identifies the coordinator's transaction record (for approvals).
	TxID string `json:"tx_id,omitempty"`
	// Approval is the user signer's approval token, checked by the server.
	Approval string `json:"approval,omitempty"`
}

// SignResult carries the verified threshold signature.
type SignResult struct {
	Party     string        `json:"party"`
	Signature mpc.Signature `json:"signature"`
	PublicKey string        `json:"public_key"`
}

func shareRecord(walletID string) string { return "share/" + walletID }

func (s *Signer) claimSession(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.usedSessions[id] {
		return fmt.Errorf("%w: %s", ErrSessionReused, id)
	}
	s.usedSessions[id] = true
	return nil
}

func (s *Signer) dial(sessionID string, members []string) (*relay.Transport, error) {
	peers := map[string]*identity.Public{}
	for _, name := range members {
		if name == s.cfg.Name {
			continue
		}
		pub, err := s.cfg.Peers.Resolve(name)
		if err != nil {
			return nil, err
		}
		peers[name] = pub
	}
	return relay.Dial(relay.TransportConfig{
		BaseURL:    s.cfg.RelayURL,
		SessionID:  sessionID,
		Self:       s.id,
		Peers:      peers,
		HTTPClient: s.cfg.HTTPClient,
		Logger:     s.log,
	})
}

// Keygen joins a distributed key generation session and stores the
// resulting share encrypted.
func (s *Signer) Keygen(ctx context.Context, req KeygenRequest) (*KeygenResult, error) {
	if !walletIDRE.MatchString(req.WalletID) {
		return nil, fmt.Errorf("%w: invalid wallet id", ErrBadRequest)
	}
	if exists, err := s.store.Has(shareRecord(req.WalletID)); err != nil {
		return nil, err
	} else if exists {
		return nil, fmt.Errorf("%w: %s", ErrWalletExists, req.WalletID)
	}
	if err := s.claimSession(req.SessionID); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.SessionTimeout)
	defer cancel()

	pre, err := s.takePreParams(ctx)
	if err != nil {
		return nil, err
	}
	tr, err := s.dial(req.SessionID, mpc.DefaultCommittee)
	if err != nil {
		return nil, err
	}
	defer tr.Close()

	s.log.Info("keygen started", "wallet", req.WalletID, "session", req.SessionID)
	share, err := mpc.Keygen(ctx, mpc.KeygenConfig{SessionID: req.SessionID, Self: s.cfg.Name, PreParams: pre}, tr)
	if err != nil {
		return nil, err
	}
	raw, err := share.Marshal()
	if err != nil {
		return nil, err
	}
	if err := s.store.Put(shareRecord(req.WalletID), raw); err != nil {
		return nil, err
	}
	pub := hex.EncodeToString(share.PublicKeyBytes())
	s.log.Info("keygen complete", "wallet", req.WalletID, "public_key", pub)
	return &KeygenResult{WalletID: req.WalletID, Party: s.cfg.Name, PublicKey: pub}, nil
}

// LoadShare decrypts this signer's share for a wallet.
func (s *Signer) LoadShare(walletID string) (*mpc.KeyShare, error) {
	if !walletIDRE.MatchString(walletID) {
		return nil, fmt.Errorf("%w: invalid wallet id", ErrBadRequest)
	}
	raw, err := s.store.Get(shareRecord(walletID))
	if errors.Is(err, sharestore.ErrNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrWalletUnknown, walletID)
	}
	if err != nil {
		return nil, err
	}
	return mpc.UnmarshalKeyShare(raw)
}

// Sign joins a signing session after the Authorizer approves the request.
func (s *Signer) Sign(ctx context.Context, req SignRequest) (*SignResult, error) {
	digest, err := hex.DecodeString(req.Digest)
	if err != nil || len(digest) != 32 {
		return nil, fmt.Errorf("%w: digest must be 32 bytes hex", ErrBadRequest)
	}
	if !slices.Contains(req.Signers, s.cfg.Name) {
		return nil, fmt.Errorf("%w: %s is not among signers %v", ErrBadRequest, s.cfg.Name, req.Signers)
	}
	share, err := s.LoadShare(req.WalletID)
	if err != nil {
		return nil, err
	}
	if err := s.cfg.Authorizer.Authorize(ctx, &req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotAuthorized, err)
	}
	if err := s.claimSession(req.SessionID); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.SessionTimeout)
	defer cancel()
	tr, err := s.dial(req.SessionID, req.Signers)
	if err != nil {
		return nil, err
	}
	defer tr.Close()

	s.log.Info("signing started", "wallet", req.WalletID, "session", req.SessionID, "signers", req.Signers)
	sig, err := mpc.Sign(ctx, mpc.SignConfig{SessionID: req.SessionID, Signers: req.Signers, Digest: digest}, share, tr)
	if err != nil {
		return nil, err
	}
	s.log.Info("signing complete", "wallet", req.WalletID, "session", req.SessionID)
	return &SignResult{Party: s.cfg.Name, Signature: *sig, PublicKey: hex.EncodeToString(share.PublicKeyBytes())}, nil
}

// Wallets lists the wallet IDs this signer holds a share for.
func (s *Signer) Wallets() ([]string, error) {
	names, err := s.store.List("share/")
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(names))
	for _, n := range names {
		ids = append(ids, n[len("share/"):])
	}
	return ids, nil
}
