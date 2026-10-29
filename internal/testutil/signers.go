// Package testutil spins up in-process signer clusters for integration tests.
package testutil

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"

	"thresholdvault/internal/chain"
	"thresholdvault/internal/mpc"
	"thresholdvault/internal/sharestore"
	"thresholdvault/internal/signer"
)

// Signer is one in-process signer with its HTTP clients.
type Signer struct {
	Signer    *signer.Signer
	Client    *signer.Client // signer API (what the coordinator uses)
	Approvals *signer.Client // user-only approval API
	Dir       string
}

// Quiet is a logger that discards output.
var Quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// Tokens used by test clusters.
const (
	SignerToken   = "token"
	ApprovalToken = "approval-token"
)

// PreParams loads the TEST-ONLY pre-parameter fixtures from internal/mpc.
func PreParams(t testing.TB, party string) *keygen.LocalPreParams {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "mpc", "testdata", "preparams-"+party+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("pre-parameter fixtures missing; run `go test ./internal/mpc` first: %v", err)
	}
	var p keygen.LocalPreParams
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

// Options configures a test cluster.
type Options struct {
	Keygens int // pooled pre-parameter sets per signer
	// Chains enables the production policies (UserPolicy for the user
	// signer, CosignerPolicy for server and backup) over this registry.
	// When nil, signers use Authorizers or allow everything.
	Chains      *chain.Registry
	Authorizers map[string]signer.Authorizer
}

// StartSigners starts the three committee signers against relayURL with
// allow-all policies (or the given authorizers).
func StartSigners(t testing.TB, relayURL string, keygens int, authorizers map[string]signer.Authorizer) map[string]*Signer {
	t.Helper()
	return StartCluster(t, relayURL, Options{Keygens: keygens, Authorizers: authorizers})
}

// StartCluster starts the three committee signers against relayURL. Each
// has its own encrypted store, signer API and approval API.
func StartCluster(t testing.TB, relayURL string, opts Options) map[string]*Signer {
	t.Helper()
	peerDir := t.TempDir()
	out := map[string]*Signer{}
	for _, name := range mpc.DefaultCommittee {
		dir := t.TempDir()
		store, err := sharestore.OpenWithKDF(dir, []byte("pass-"+name), sharestore.KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1})
		if err != nil {
			t.Fatal(err)
		}
		peers := &signer.DirPeers{Dir: peerDir, Store: store}
		var auth signer.Authorizer
		switch {
		case opts.Chains != nil && name == mpc.PartyUser:
			auth = &signer.UserPolicy{Store: store, Chains: opts.Chains}
		case opts.Chains != nil:
			auth = &signer.CosignerPolicy{Peers: peers, Chains: opts.Chains}
		case opts.Authorizers[name] != nil:
			auth = opts.Authorizers[name]
		default:
			auth = signer.AuthorizerFunc(func(context.Context, *signer.SignRequest) error { return nil })
		}
		s, err := signer.New(signer.Config{
			Name: name, Store: store, RelayURL: relayURL, Peers: peers, Chains: opts.Chains,
			Authorizer: auth, Logger: Quiet, SessionTimeout: 30 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := signer.PublishIdentity(peerDir, s.Identity()); err != nil {
			t.Fatal(err)
		}
		pre := PreParams(t, name)
		for range opts.Keygens {
			if err := s.AddPreParams(pre); err != nil {
				t.Fatal(err)
			}
		}
		srv := httptest.NewServer(s.Handler(SignerToken))
		t.Cleanup(srv.Close)
		approvals := httptest.NewServer(s.ApprovalHandler(ApprovalToken))
		t.Cleanup(approvals.Close)
		out[name] = &Signer{
			Signer: s, Dir: dir,
			Client:    signer.NewClient(srv.URL, SignerToken),
			Approvals: signer.NewClient(approvals.URL, ApprovalToken),
		}
	}
	return out
}
