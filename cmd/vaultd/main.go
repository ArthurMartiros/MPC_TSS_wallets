// Command vaultd runs the ThresholdVault coordinator: REST API, SQLite
// metadata store and the MPC message relay. It holds no key material.
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
	"syscall"
	"time"

	"thresholdvault/internal/api"
	"thresholdvault/internal/chain"
	"thresholdvault/internal/chain/evm"
	"thresholdvault/internal/chain/networks"
	"thresholdvault/internal/coordinator"
	"thresholdvault/internal/relay"
	"thresholdvault/internal/signer"
	"thresholdvault/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "vaultd:", err)
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
		listen      = flag.String("listen", env("VAULT_LISTEN", "127.0.0.1:8080"), "HTTP listen address")
		dbPath      = flag.String("db", env("VAULT_DB", "thresholdvault.db"), "SQLite database path")
		apiToken    = flag.String("api-token", env("VAULT_API_TOKEN", ""), "bearer token required by the REST API")
		signerToken = flag.String("signer-token", env("SIGNER_API_TOKEN", ""), "bearer token presented to signers")
		userURL     = flag.String("signer-user", env("VAULT_SIGNER_USER", "http://127.0.0.1:7001"), "user signer URL")
		serverURL   = flag.String("signer-server", env("VAULT_SIGNER_SERVER", "http://127.0.0.1:7002"), "server signer URL")
		backupURL   = flag.String("signer-backup", env("VAULT_SIGNER_BACKUP", "http://127.0.0.1:7003"), "backup signer URL")
		sepoliaRPC  = flag.String("sepolia-rpc", env("SEPOLIA_RPC_URL", ""), "Ethereum Sepolia JSON-RPC URL")
		bscRPC      = flag.String("bsc-rpc", env("BSC_TESTNET_RPC_URL", ""), "BSC testnet JSON-RPC URL")
		tronAPI     = flag.String("tron-api", env("TRON_NILE_API_URL", ""), "TRON Nile HTTP API URL")
		logFormat   = flag.String("log", env("VAULT_LOG", "text"), "log format: text | json")
	)
	flag.Parse()

	var handler slog.Handler = slog.NewTextHandler(os.Stderr, nil)
	if *logFormat == "json" {
		handler = slog.NewJSONHandler(os.Stderr, nil)
	}
	log := slog.New(handler)

	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	chains := networks.Default(networks.RPC{Sepolia: *sepoliaRPC, BSCTestnet: *bscRPC, TronNile: *tronAPI})
	nodes := map[string]chain.Node{}
	for id, url := range map[string]string{networks.EthereumSepolia: *sepoliaRPC, networks.BSCTestnet: *bscRPC} {
		if url == "" {
			log.Info("no RPC configured; balances and transactions disabled", "chain", id)
			continue
		}
		c, err := chains.Get(id)
		if err != nil {
			return err
		}
		n, err := evm.Dial(context.Background(), c.(*evm.Chain), url)
		if err != nil {
			return err
		}
		nodes[id] = n
		log.Info("RPC configured", "chain", id) // URL not logged: it often embeds an API key
	}

	coord, err := coordinator.New(coordinator.Config{
		Store:  st,
		Chains: chains,
		Nodes:  nodes,
		Signers: map[string]coordinator.SignerAPI{
			"user":   signer.NewClient(*userURL, *signerToken),
			"server": signer.NewClient(*serverURL, *signerToken),
			"backup": signer.NewClient(*backupURL, *signerToken),
		},
		Logger: log,
	})
	if err != nil {
		return err
	}
	if *apiToken == "" {
		log.Warn("no --api-token set; the REST API is unauthenticated")
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           (&api.Server{Coord: coord, Relay: relay.NewServer(), Token: *apiToken, Logger: log}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	log.Info("vaultd listening", "addr", *listen, "db", *dbPath)

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
