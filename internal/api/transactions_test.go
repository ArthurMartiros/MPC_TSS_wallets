package api

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"

	"thresholdvault/internal/chain"
	"thresholdvault/internal/chain/evm"
	"thresholdvault/internal/coordinator"
	"thresholdvault/internal/relay"
	"thresholdvault/internal/signer"
	"thresholdvault/internal/store"
	"thresholdvault/internal/testutil"
)

const simChain = "evm-simulated"

func ether(s string) *big.Int {
	v, err := chain.ParseAmount(s, 18)
	if err != nil {
		panic(err)
	}
	return v
}

// txHarness is the full stack against go-ethereum's in-memory chain:
// REST API + coordinator + three signers with the production policies.
type txHarness struct {
	*harness
	backend *simulated.Backend
	chainID *big.Int
	faucet  *ecdsa.PrivateKey
	user    *testutil.Signer
}

func newTxHarness(t *testing.T) *txHarness {
	t.Helper()
	faucet, _ := ethcrypto.GenerateKey()
	backend := simulated.NewBackend(types.GenesisAlloc{
		ethcrypto.PubkeyToAddress(faucet.PublicKey): {Balance: ether("1000")},
	})
	t.Cleanup(func() { backend.Close() })
	chainID, err := backend.Client().ChainID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	evmChain := evm.New(evm.Config{
		ID: simChain, Name: "Simulated EVM", ChainID: chainID,
		Native: chain.Asset{Symbol: "ETH", Decimals: 18, Standard: "native"},
	})
	chains := chain.NewRegistry(evmChain)

	var handler atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.Load().(http.Handler).ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	signers := testutil.StartCluster(t, srv.URL, testutil.Options{Keygens: 1, Chains: chains})
	st, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	clients := map[string]coordinator.SignerAPI{}
	for name, s := range signers {
		clients[name] = s.Client
	}
	coord, err := coordinator.New(coordinator.Config{
		Store: st, Chains: chains, Signers: clients, Logger: testutil.Quiet,
		Nodes: map[string]chain.Node{simChain: evm.NewNode(evmChain, backend.Client())},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler.Store((&Server{Coord: coord, Relay: relay.NewServer(), Token: apiToken, Logger: testutil.Quiet}).Handler())
	return &txHarness{harness: &harness{url: srv.URL, t: t}, backend: backend, chainID: chainID, faucet: faucet, user: signers["user"]}
}

// fund sends ETH from the faucet (an ordinary key) and mines a block.
func (h *txHarness) fund(to string, amount *big.Int) {
	h.t.Helper()
	ctx := context.Background()
	client := h.backend.Client()
	from := ethcrypto.PubkeyToAddress(h.faucet.PublicKey)
	nonce, _ := client.PendingNonceAt(ctx, from)
	head, _ := client.HeaderByNumber(ctx, nil)
	toAddr := common.HexToAddress(to)
	tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		ChainID: h.chainID, Nonce: nonce, GasTipCap: big.NewInt(1e9),
		GasFeeCap: new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), big.NewInt(1e9)),
		Gas:       21000, To: &toAddr, Value: amount,
	}), types.LatestSignerForChainID(h.chainID), h.faucet)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := client.SendTransaction(ctx, tx); err != nil {
		h.t.Fatal(err)
	}
	h.backend.Commit()
}

// userApproves plays the user: the user signer decodes the transaction
// itself, the user checks it, and confirms.
func (h *txHarness) userApproves(tx *store.Transaction) string {
	h.t.Helper()
	ctx := context.Background()
	rev, err := h.user.Approvals.Review(ctx, signer.ReviewRequest{TxID: tx.ID, WalletID: tx.WalletID, Chain: tx.Chain, Transaction: tx.UnsignedTx})
	if err != nil {
		h.t.Fatal(err)
	}
	if rev.From != tx.From || rev.Summary.To != tx.To || rev.Summary.Amount != tx.Amount {
		h.t.Fatalf("user signer's reading %+v differs from the coordinator's %+v", rev.Summary, tx)
	}
	conf, err := h.user.Approvals.Confirm(ctx, signer.ConfirmRequest{TxID: tx.ID, Sighash: rev.Summary.Sighash})
	if err != nil {
		h.t.Fatal(err)
	}
	return conf.Approval
}

func TestEndToEndTransferOnSimulatedChain(t *testing.T) {
	h := newTxHarness(t)
	var w store.Wallet
	if code := h.do("POST", "/wallets", apiToken, map[string]string{"name": "e2e"}, &w); code != http.StatusCreated {
		t.Fatalf("create wallet: %d", code)
	}
	from, _ := w.AddressFor(simChain)
	h.fund(from, ether("5"))

	var bal coordinator.BalanceResult
	if code := h.do("GET", "/wallets/"+w.ID+"/balance?chain="+simChain, apiToken, nil, &bal); code != 200 || bal.BalanceDisplay != "5 ETH" {
		t.Fatalf("balance: %d %+v", code, bal)
	}

	recipient := "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF"
	var tx store.Transaction
	code := h.do("POST", "/transactions/prepare", apiToken, coordinator.PrepareRequest{
		WalletID: w.ID, Chain: simChain, Asset: "ETH", To: recipient, Amount: "1.5",
	}, &tx)
	if code != http.StatusCreated || tx.Status != store.TxPrepared || tx.Summary.AmountDisplay != "1.5 ETH" {
		t.Fatalf("prepare: %d %+v", code, tx)
	}

	// Signing before approval is refused by the coordinator.
	if code := h.do("POST", "/transactions/"+tx.ID+"/sign", apiToken, nil, nil); code != http.StatusConflict {
		t.Fatalf("sign before approve: want 409, got %d", code)
	}
	// A made-up approval is rejected.
	if code := h.do("POST", "/transactions/"+tx.ID+"/approve", apiToken, ApproveRequest{Approval: "forged"}, nil); code != http.StatusBadRequest {
		t.Fatalf("forged approval: want 400, got %d", code)
	}

	approvalTok := h.userApproves(&tx)
	if code := h.do("POST", "/transactions/"+tx.ID+"/approve", apiToken, ApproveRequest{Approval: approvalTok}, &tx); code != 200 || tx.Status != store.TxApproved {
		t.Fatalf("approve: %d %+v", code, tx)
	}
	if code := h.do("POST", "/transactions/"+tx.ID+"/broadcast", apiToken, nil, nil); code != http.StatusConflict {
		t.Fatalf("broadcast before sign: want 409, got %d", code)
	}
	if code := h.do("POST", "/transactions/"+tx.ID+"/sign", apiToken, nil, &tx); code != 200 || tx.Status != store.TxSigned || tx.TxHash == "" {
		t.Fatalf("sign: %d %+v", code, tx)
	}
	if code := h.do("POST", "/transactions/"+tx.ID+"/broadcast", apiToken, nil, &tx); code != 200 || tx.Status != store.TxBroadcast {
		t.Fatalf("broadcast: %d %+v", code, tx)
	}
	h.backend.Commit()

	if code := h.do("GET", "/transactions/"+tx.ID, apiToken, nil, &tx); code != 200 || tx.Status != store.TxConfirmed || tx.BlockNumber == 0 {
		t.Fatalf("after mining: %d %+v", code, tx)
	}
	got, err := h.backend.Client().BalanceAt(context.Background(), common.HexToAddress(recipient), nil)
	if err != nil || got.Cmp(ether("1.5")) != 0 {
		t.Fatalf("recipient balance %s %v", got, err)
	}
	t.Logf("threshold-signed tx %s mined in block %d", tx.TxHash, tx.BlockNumber)

	var list []store.Transaction
	if code := h.do("GET", "/transactions?wallet_id="+w.ID, apiToken, nil, &list); code != 200 || len(list) != 1 {
		t.Fatalf("list: %d %v", code, list)
	}
}

func TestTransactionErrors(t *testing.T) {
	h := newTxHarness(t)
	var w store.Wallet
	if code := h.do("POST", "/wallets", apiToken, map[string]string{"name": "e"}, &w); code != http.StatusCreated {
		t.Fatalf("create wallet: %d", code)
	}
	prep := func(req coordinator.PrepareRequest) int {
		req.WalletID = w.ID
		return h.do("POST", "/transactions/prepare", apiToken, req, nil)
	}
	to := "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF"
	if code := prep(coordinator.PrepareRequest{Chain: simChain, To: to, Amount: "1"}); code != http.StatusBadRequest {
		t.Errorf("unfunded wallet: want 400, got %d", code)
	}
	h.fund(func() string { a, _ := w.AddressFor(simChain); return a }(), ether("1"))
	cases := map[string]coordinator.PrepareRequest{
		"bad address":       {Chain: simChain, To: "0x123", Amount: "0.1"},
		"too many decimals": {Chain: simChain, To: to, Amount: "0.0000000000000000001"},
		"zero amount":       {Chain: simChain, To: to, Amount: "0"},
		"unknown asset":     {Chain: simChain, Asset: "DOGE", To: to, Amount: "1"},
		"unknown chain":     {Chain: "nope", To: to, Amount: "1"},
	}
	for name, req := range cases {
		if code := prep(req); code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", name, code)
		}
	}
	if code := h.do("GET", "/transactions/tx_missing", apiToken, nil, nil); code != http.StatusNotFound {
		t.Errorf("missing tx: %d", code)
	}
	if code := h.do("GET", "/wallets/"+w.ID+"/balance", apiToken, nil, nil); code != http.StatusBadRequest {
		t.Errorf("balance without chain: %d", code)
	}
}

func TestChainWithoutRPCIsNotImplemented(t *testing.T) {
	h := newHarness(t) // default registry, no nodes configured
	var w store.Wallet
	if code := h.do("POST", "/wallets", apiToken, map[string]string{"name": "x"}, &w); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	if code := h.do("GET", "/wallets/"+w.ID+"/balance?chain=bitcoin-testnet", apiToken, nil, nil); code != http.StatusNotImplemented {
		t.Errorf("balance without RPC: want 501, got %d", code)
	}
	if code := h.do("POST", "/transactions/prepare", apiToken, coordinator.PrepareRequest{
		WalletID: w.ID, Chain: "ethereum-sepolia", To: "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF", Amount: "1",
	}, nil); code != http.StatusNotImplemented {
		t.Errorf("prepare without RPC: want 501, got %d", code)
	}
}
