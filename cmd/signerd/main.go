// Command signerd runs one ThresholdVault MPC signer node (user, server or
// backup). Each node keeps its own encrypted key shares and talks to the
// other signers only through the coordinator's relay, end-to-end encrypted.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"thresholdvault/internal/chain"
	"thresholdvault/internal/chain/networks"
	"thresholdvault/internal/sharestore"
	"thresholdvault/internal/signer"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "signerd:", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func run() error {
	var (
		name      = flag.String("name", env("SIGNER_NAME", ""), "committee role: user | server | backup")
		listen    = flag.String("listen", env("SIGNER_LISTEN", "127.0.0.1:7001"), "HTTP listen address")
		dataDir   = flag.String("data-dir", env("SIGNER_DATA_DIR", ""), "directory for this signer's encrypted shares")
		passFile  = flag.String("passphrase-file", env("SIGNER_PASSPHRASE_FILE", ""), "file containing the share encryption passphrase (or set SIGNER_PASSPHRASE)")
		relayURL  = flag.String("relay-url", env("SIGNER_RELAY_URL", "http://127.0.0.1:8080"), "coordinator relay base URL")
		peersDir  = flag.String("peers-dir", env("SIGNER_PEERS_DIR", ""), "directory of <name>.pub peer identities (pinned on first use)")
		apiToken  = flag.String("api-token", env("SIGNER_API_TOKEN", ""), "bearer token the coordinator must present")
		poolSize  = flag.Int("preparams-pool", 1, "pre-parameter sets to keep ready")
		policy    = flag.String("policy", env("SIGNER_POLICY", ""), "signing policy: user | cosigner | deny | dev-allow-all (default: user for the user signer, cosigner otherwise)")
		apprAddr  = flag.String("approval-listen", env("SIGNER_APPROVAL_LISTEN", "127.0.0.1:7101"), "user policy: listen address of the user-only approval API")
		apprToken = flag.String("approval-token", env("SIGNER_APPROVAL_TOKEN", ""), "user policy: bearer token for the approval API (never give it to the coordinator)")
		logFormat = flag.String("log", env("SIGNER_LOG", "text"), "log format: text | json")
	)
	flag.Parse()
	if *policy == "" {
		*policy = "cosigner"
		if *name == "user" {
			*policy = "user"
		}
	}

	var handler slog.Handler = slog.NewTextHandler(os.Stderr, nil)
	if *logFormat == "json" {
		handler = slog.NewJSONHandler(os.Stderr, nil)
	}
	log := slog.New(handler)

	if *name == "" || *dataDir == "" || *peersDir == "" {
		return errors.New("--name, --data-dir and --peers-dir are required")
	}
	pass, err := readPassphrase(*passFile)
	if err != nil {
		return err
	}
	store, err := sharestore.Open(*dataDir, pass)
	if err != nil {
		return err
	}

	// Signers decode transactions offline; they need no RPC endpoints.
	chains := networks.Default(networks.RPC{})
	peers := &signer.DirPeers{Dir: *peersDir, Store: store}
	auth, err := authorizer(*policy, store, peers, chains, log)
	if err != nil {
		return err
	}
	if *policy == "user" && *apprToken == "" {
		return errors.New("policy=user requires --approval-token (or SIGNER_APPROVAL_TOKEN)")
	}
	s, err := signer.New(signer.Config{
		Name:       *name,
		Store:      store,
		RelayURL:   strings.TrimRight(*relayURL, "/"),
		Peers:      peers,
		Authorizer: auth,
		Chains:     chains,
		Logger:     log,
	})
	if err != nil {
		return err
	}
	if err := signer.PublishIdentity(*peersDir, s.Identity()); err != nil {
		return fmt.Errorf("publish identity: %w", err)
	}
	log.Info("signer identity", "name", *name, "fingerprint", s.Identity().Fingerprint())
	if *apiToken == "" {
		log.Warn("no --api-token set; anyone who can reach the signer API can request sessions")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go s.RunPreParamsPool(ctx, *poolSize)

	servers := []*http.Server{{Addr: *listen, Handler: s.Handler(*apiToken), ReadHeaderTimeout: 10 * time.Second}}
	if *policy == "user" {
		servers = append(servers, &http.Server{Addr: *apprAddr, Handler: s.ApprovalHandler(*apprToken), ReadHeaderTimeout: 10 * time.Second})
	}
	errCh := make(chan error, len(servers))
	for _, srv := range servers {
		go func() { errCh <- srv.ListenAndServe() }()
	}
	log.Info("signer listening", "addr", *listen, "relay", *relayURL, "policy", *policy)
	if *policy == "user" {
		log.Info("approval API listening (user only)", "addr", *apprAddr)
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdownCtx)
	}
	return nil
}

func readPassphrase(file string) ([]byte, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read passphrase file: %w", err)
		}
		return []byte(strings.TrimRight(string(b), "\r\n")), nil
	}
	if p := os.Getenv("SIGNER_PASSPHRASE"); p != "" {
		return []byte(p), nil
	}
	return nil, errors.New("no passphrase: set --passphrase-file or SIGNER_PASSPHRASE")
}

func authorizer(policy string, store *sharestore.Store, peers signer.PeerResolver, chains *chain.Registry, log *slog.Logger) (signer.Authorizer, error) {
	switch policy {
	case "user":
		return &signer.UserPolicy{Store: store, Chains: chains}, nil
	case "cosigner":
		return &signer.CosignerPolicy{Peers: peers, Chains: chains}, nil
	case "deny":
		return signer.AuthorizerFunc(func(context.Context, *signer.SignRequest) error {
			return errors.New("policy=deny: no signing policy configured")
		}), nil
	case "dev-allow-all":
		log.Warn("DEVELOPMENT POLICY: this signer will sign ANY digest it is asked to. Never use with real funds.")
		return signer.AuthorizerFunc(func(context.Context, *signer.SignRequest) error { return nil }), nil
	default:
		return nil, fmt.Errorf("unknown policy %q", policy)
	}
}
