package signer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"thresholdvault/internal/chain/networks"
	"thresholdvault/internal/identity"
	"thresholdvault/internal/mpc"
	"thresholdvault/internal/relay"
	"thresholdvault/internal/sharestore"
)

var cheapKDF = sharestore.KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1}

const testToken = "test-token"

type node struct {
	signer    *Signer
	client    *Client
	approvals *Client // user-only approval API
	dir       string
}

type cluster struct {
	nodes   map[string]*node
	peerDir string
}

func allow(context.Context, *SignRequest) error { return nil }

// fixturePreParams loads the test-only pre-parameters cached by internal/mpc.
func fixturePreParams(t *testing.T, party string) *keygen.LocalPreParams {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "mpc", "testdata", "preparams-"+party+".json"))
	if err != nil {
		t.Skipf("pre-parameter fixtures missing; run `go test ./internal/mpc` first: %v", err)
	}
	var p keygen.LocalPreParams
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

// authFactory builds a signer's Authorizer from that signer's own store and
// peer resolver.
type authFactory func(name string, store *sharestore.Store, peers PeerResolver) Authorizer

// fixed returns a factory using the given per-role authorizers, allowing
// everything for roles not listed.
func fixed(m map[string]Authorizer) authFactory {
	return func(name string, _ *sharestore.Store, _ PeerResolver) Authorizer {
		if a := m[name]; a != nil {
			return a
		}
		return AuthorizerFunc(allow)
	}
}

const approvalToken = "approval-token"

func newCluster(t *testing.T, mkAuth authFactory) *cluster {
	t.Helper()
	if mkAuth == nil {
		mkAuth = fixed(nil)
	}
	relaySrv := httptest.NewServer(relay.NewServer().Handler())
	t.Cleanup(relaySrv.Close)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	chains := networks.Default(networks.RPC{})

	c := &cluster{nodes: map[string]*node{}, peerDir: t.TempDir()}
	for _, name := range mpc.DefaultCommittee {
		dir := t.TempDir()
		store, err := sharestore.OpenWithKDF(dir, []byte("pass-"+name), cheapKDF)
		if err != nil {
			t.Fatal(err)
		}
		peers := &DirPeers{Dir: c.peerDir, Store: store}
		s, err := New(Config{
			Name:           name,
			Store:          store,
			RelayURL:       relaySrv.URL,
			Peers:          peers,
			Authorizer:     mkAuth(name, store, peers),
			Chains:         chains,
			Logger:         quiet,
			SessionTimeout: 30 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := PublishIdentity(c.peerDir, s.Identity()); err != nil {
			t.Fatal(err)
		}
		if err := s.AddPreParams(fixturePreParams(t, name)); err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(s.Handler(testToken))
		t.Cleanup(srv.Close)
		approvalSrv := httptest.NewServer(s.ApprovalHandler(approvalToken))
		t.Cleanup(approvalSrv.Close)
		c.nodes[name] = &node{
			signer: s, client: NewClient(srv.URL, testToken), dir: dir,
			approvals: NewClient(approvalSrv.URL, approvalToken),
		}
	}
	return c
}

func (c *cluster) keygen(t *testing.T, walletID string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		pubs = map[string]string{}
		errs []error
	)
	for name, n := range c.nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := n.client.Keygen(ctx, KeygenRequest{SessionID: "kg-" + walletID, WalletID: walletID})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
				return
			}
			pubs[name] = res.PublicKey
		}()
	}
	wg.Wait()
	if len(errs) > 0 {
		t.Fatal(errors.Join(errs...))
	}
	if pubs["user"] != pubs["server"] || pubs["server"] != pubs["backup"] {
		t.Fatalf("signers disagree on public key: %v", pubs)
	}
	return pubs["user"]
}

func (c *cluster) sign(ctx context.Context, sessionID, walletID string, signers []string, digest []byte) (map[string]*SignResult, error) {
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		out  = map[string]*SignResult{}
		errs []error
	)
	for _, name := range signers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := c.nodes[name].client.Sign(ctx, SignRequest{SessionID: sessionID, WalletID: walletID, Signers: signers, Digest: hex.EncodeToString(digest)})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
				return
			}
			out[name] = res
		}()
	}
	wg.Wait()
	return out, errors.Join(errs...)
}

func TestKeygenAndSignAcrossIndependentSigners(t *testing.T) {
	c := newCluster(t, nil)
	pubHex := c.keygen(t, "wallet-1")
	pubBytes, _ := hex.DecodeString(pubHex)
	pub, err := ethcrypto.DecompressPubkey(pubBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Each signer holds exactly one share, for its own party, in its own store.
	for name, n := range c.nodes {
		share, err := n.signer.LoadShare("wallet-1")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if share.Party != name {
			t.Fatalf("%s holds a share for %s", name, share.Party)
		}
		if _, err := os.Stat(filepath.Join(n.dir, "share", "wallet-1.enc")); err != nil {
			t.Fatalf("%s: encrypted share file missing: %v", name, err)
		}
	}

	for i, signers := range [][]string{{"user", "server"}, {"server", "backup"}} {
		digest := sha256.Sum256(fmt.Appendf(nil, "tx %d", i))
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		res, err := c.sign(ctx, fmt.Sprintf("sign-%d", i), "wallet-1", signers, digest[:])
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		sig := res[signers[0]].Signature
		if err := sig.Verify(pub, digest[:]); err != nil {
			t.Fatalf("%v: %v", signers, err)
		}
	}
}

func TestAuthorizerRefusalBlocksSigning(t *testing.T) {
	refuse := AuthorizerFunc(func(context.Context, *SignRequest) error { return errors.New("user did not approve") })
	c := newCluster(t, fixed(map[string]Authorizer{"user": refuse}))
	c.keygen(t, "w")
	digest := sha256.Sum256([]byte("unapproved"))
	_, err := c.nodes["user"].client.Sign(context.Background(), SignRequest{
		SessionID: "s-refused", WalletID: "w", Signers: []string{"user", "server"}, Digest: hex.EncodeToString(digest[:]),
	})
	if !isStatus(err, http.StatusForbidden) {
		t.Fatalf("want 403 from user signer, got %v", err)
	}
	// Without the user, the server can't finish the protocol on its own.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := c.nodes["server"].client.Sign(ctx, SignRequest{
		SessionID: "s-refused", WalletID: "w", Signers: []string{"user", "server"}, Digest: hex.EncodeToString(digest[:]),
	}); err == nil {
		t.Fatal("server produced a signature without the user")
	}
}

func TestSessionAndWalletReuseRejected(t *testing.T) {
	c := newCluster(t, nil)
	c.keygen(t, "w")
	ctx := context.Background()
	if _, err := c.nodes["user"].client.Keygen(ctx, KeygenRequest{SessionID: "kg-other", WalletID: "w"}); !isStatus(err, http.StatusConflict) {
		t.Fatalf("duplicate wallet: want 409, got %v", err)
	}
	digest := hex.EncodeToString(make([]byte, 32))
	if _, err := c.nodes["user"].client.Sign(ctx, SignRequest{SessionID: "kg-w", WalletID: "w", Signers: []string{"user", "server"}, Digest: digest}); !isStatus(err, http.StatusConflict) {
		t.Fatalf("reused session: want 409, got %v", err)
	}
	if _, err := c.nodes["user"].client.Sign(ctx, SignRequest{SessionID: "x", WalletID: "nope", Signers: []string{"user", "server"}, Digest: digest}); !isStatus(err, http.StatusNotFound) {
		t.Fatalf("unknown wallet: want 404, got %v", err)
	}
	if _, err := c.nodes["user"].client.Sign(ctx, SignRequest{SessionID: "y", WalletID: "w", Signers: []string{"user"}, Digest: digest}); !isStatus(err, http.StatusBadRequest) {
		t.Fatalf("single signer: want 400, got %v", err)
	}
}

func TestBearerTokenRequired(t *testing.T) {
	c := newCluster(t, nil)
	cl := *c.nodes["server"].client
	cl.Token = "wrong"
	if _, err := cl.Health(context.Background()); !isStatus(err, http.StatusUnauthorized) {
		t.Fatalf("want 401, got %v", err)
	}
}

func TestPeerIdentityIsPinned(t *testing.T) {
	c := newCluster(t, nil)
	user := c.nodes["user"].signer
	resolver := user.cfg.Peers
	if _, err := resolver.Resolve("server"); err != nil {
		t.Fatal(err)
	}
	// An attacker with write access to the shared directory swaps the key.
	evil, _ := identity.Generate("server")
	if err := PublishIdentity(c.peerDir, &evil.Public); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve("server"); err == nil {
		t.Fatal("accepted a substituted peer identity")
	}
}

func TestIdentityPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	open := func() *Signer {
		store, _ := sharestore.OpenWithKDF(dir, []byte("pw"), cheapKDF)
		s, err := New(Config{Name: "server", Store: store, RelayURL: "http://x", Peers: StaticPeers{}, Authorizer: AuthorizerFunc(allow)})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	a, b := open(), open()
	if !a.Identity().Equal(b.Identity()) {
		t.Fatal("identity changed across restart")
	}
	store, _ := sharestore.OpenWithKDF(dir, []byte("pw"), cheapKDF)
	if _, err := New(Config{Name: "user", Store: store, RelayURL: "http://x", Peers: StaticPeers{}, Authorizer: AuthorizerFunc(allow)}); err == nil {
		t.Fatal("store reused under a different role")
	}
}

func isStatus(err error, status int) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Status == status
}
