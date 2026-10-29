package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"thresholdvault/internal/chain/networks"
	"thresholdvault/internal/coordinator"
	"thresholdvault/internal/relay"
	"thresholdvault/internal/store"
	"thresholdvault/internal/testutil"
)

const apiToken = "api-token"

type harness struct {
	url string
	t   *testing.T
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	// The API server hosts the relay, so signers need its URL first.
	var handler atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.Load().(http.Handler).ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	signers := testutil.StartSigners(t, srv.URL, 2, nil)
	st, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	clients := map[string]coordinator.SignerAPI{}
	for name, s := range signers {
		clients[name] = s.Client
	}
	coord, err := coordinator.New(coordinator.Config{Store: st, Chains: networks.Default(networks.RPC{}), Signers: clients, Logger: testutil.Quiet})
	if err != nil {
		t.Fatal(err)
	}
	api := &Server{Coord: coord, Relay: relay.NewServer(), Token: apiToken, Logger: testutil.Quiet}
	handler.Store(api.Handler())
	return &harness{url: srv.URL, t: t}
}

func (h *harness) do(method, path, token string, body any, out any) int {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.url+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(raw, out); err != nil {
			h.t.Fatalf("decode %s: %v\n%s", path, err, raw)
		}
	}
	return resp.StatusCode
}

func TestWalletLifecycle(t *testing.T) {
	h := newHarness(t)

	var w store.Wallet
	if code := h.do("POST", "/wallets", apiToken, map[string]string{"name": "treasury"}, &w); code != http.StatusCreated {
		t.Fatalf("create wallet: %d", code)
	}
	raw, err := hex.DecodeString(w.PublicKey)
	if err != nil || len(raw) != 33 {
		t.Fatalf("bad public key %q", w.PublicKey)
	}
	pub, err := ethcrypto.DecompressPubkey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Addresses) != 6 {
		t.Fatalf("want 6 addresses, got %v", w.Addresses)
	}
	eth, _ := w.AddressFor(networks.EthereumSepolia)
	if eth != ethcrypto.PubkeyToAddress(*pub).Hex() {
		t.Errorf("ethereum address %s does not match public key", eth)
	}
	prefixes := map[string]string{
		networks.BitcoinTestnet: "tb1q", networks.LitecoinTestnet: "tltc1q",
		networks.DashTestnet: "y", networks.TronNile: "T", networks.BSCTestnet: "0x",
	}
	for chainID, prefix := range prefixes {
		if a, _ := w.AddressFor(chainID); !strings.HasPrefix(a, prefix) {
			t.Errorf("%s address %q lacks prefix %q", chainID, a, prefix)
		}
	}
	t.Logf("wallet %s: %v", w.ID, w.Addresses)

	var list []store.Wallet
	if code := h.do("GET", "/wallets", apiToken, nil, &list); code != 200 || len(list) != 1 || list[0].ID != w.ID {
		t.Fatalf("list wallets: %d %v", code, list)
	}
	var got store.Wallet
	if code := h.do("GET", "/wallets/"+w.ID, apiToken, nil, &got); code != 200 || got.PublicKey != w.PublicKey {
		t.Fatalf("get wallet: %d %+v", code, got)
	}
	if code := h.do("GET", "/wallets/w_missing", apiToken, nil, nil); code != http.StatusNotFound {
		t.Fatalf("missing wallet: %d", code)
	}

	// A second wallet gets a different key.
	var w2 store.Wallet
	if code := h.do("POST", "/wallets", apiToken, map[string]string{"name": "ops"}, &w2); code != http.StatusCreated {
		t.Fatalf("create second wallet: %d", code)
	}
	if w2.PublicKey == w.PublicKey {
		t.Fatal("two wallets share a public key")
	}
}

func TestAuthAndValidation(t *testing.T) {
	h := newHarness(t)
	if code := h.do("GET", "/healthz", "", nil, nil); code != 200 {
		t.Errorf("healthz: %d", code)
	}
	if code := h.do("GET", "/wallets", "", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	if code := h.do("GET", "/wallets", "wrong", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", code)
	}
	if code := h.do("POST", "/wallets", apiToken, map[string]string{"name": " "}, nil); code != http.StatusBadRequest {
		t.Errorf("blank name: %d", code)
	}
	if code := h.do("POST", "/wallets", apiToken, map[string]any{"name": "x", "extra": 1}, nil); code != http.StatusBadRequest {
		t.Errorf("unknown field: %d", code)
	}
	var statuses []coordinator.SignerStatus
	if code := h.do("GET", "/signers", apiToken, nil, &statuses); code != 200 || len(statuses) != 3 {
		t.Fatalf("signers: %d %v", code, statuses)
	}
	for _, s := range statuses {
		if !s.Reachable || s.Fingerprint == "" {
			t.Errorf("signer %s not reachable: %s", s.Name, s.Error)
		}
	}
	var chains []map[string]any
	if code := h.do("GET", "/chains", apiToken, nil, &chains); code != 200 || len(chains) != 6 {
		t.Fatalf("chains: %d %v", code, chains)
	}
}
