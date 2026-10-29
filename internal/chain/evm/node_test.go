package evm

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"

	"thresholdvault/internal/chain"
)

func eth(n int64) *big.Int { return new(big.Int).Mul(big.NewInt(n), big.NewInt(1e18)) }

// TestNativeTransferOnSimulatedChain runs build -> decode -> sign ->
// broadcast -> receipt against go-ethereum's in-memory chain.
func TestNativeTransferOnSimulatedChain(t *testing.T) {
	key, _ := ethcrypto.GenerateKey()
	from := ethcrypto.PubkeyToAddress(key.PublicKey)
	backend := simulated.NewBackend(types.GenesisAlloc{from: {Balance: eth(10)}})
	defer backend.Close()
	client := backend.Client()
	ctx := context.Background()
	chainID, err := client.ChainID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c := New(Config{ID: "simulated", ChainID: chainID, Native: chain.Asset{Symbol: "ETH", Decimals: 18, Standard: "native"}})
	node := NewNode(c, client)

	recipient := "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF"
	amount, _ := chain.ParseAmount("1.25", 18)
	raw, err := node.BuildTransfer(ctx, from.Hex(), recipient, c.Assets()[0], amount)
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.DecodeUnsigned(raw)
	if err != nil {
		t.Fatal(err)
	}
	if s.AmountDisplay != "1.25 ETH" || s.To != recipient || s.Nonce != 0 {
		t.Fatalf("summary %+v", s)
	}
	digest, _ := hex.DecodeString(s.Sighash)
	sig, _ := ethcrypto.Sign(digest, key)
	signed, hash, err := c.ApplySignature(raw, sig, from.Hex())
	if err != nil {
		t.Fatal(err)
	}
	if r, err := node.Receipt(ctx, hash); err != nil || r.Status != chain.TxPending {
		t.Fatalf("status before broadcast = %+v, %v", r, err)
	}
	got, err := node.Broadcast(ctx, signed)
	if err != nil || got != hash {
		t.Fatalf("broadcast: %s %v", got, err)
	}
	if _, err := node.Broadcast(ctx, signed); err != nil {
		t.Fatalf("re-broadcast should be idempotent: %v", err)
	}
	backend.Commit()

	r, err := node.Receipt(ctx, hash)
	if err != nil || r.Status != chain.TxConfirmed || r.BlockNumber == 0 {
		t.Fatalf("receipt %+v %v", r, err)
	}
	bal, err := node.Balance(ctx, recipient, c.Assets()[0])
	if err != nil || bal.Cmp(amount) != 0 {
		t.Fatalf("recipient balance %s %v", bal, err)
	}
	// Next transfer picks up the incremented nonce.
	raw2, err := node.BuildTransfer(ctx, from.Hex(), recipient, c.Assets()[0], amount)
	if err != nil {
		t.Fatal(err)
	}
	if s2, _ := c.DecodeUnsigned(raw2); s2.Nonce != 1 {
		t.Fatalf("second nonce = %d", s2.Nonce)
	}
}

func TestBuildTransferChecks(t *testing.T) {
	key, _ := ethcrypto.GenerateKey()
	from := ethcrypto.PubkeyToAddress(key.PublicKey)
	backend := simulated.NewBackend(types.GenesisAlloc{from: {Balance: eth(1)}})
	defer backend.Close()
	ctx := context.Background()
	chainID, _ := backend.Client().ChainID(ctx)
	native := chain.Asset{Symbol: "ETH", Decimals: 18, Standard: "native"}

	node := NewNode(New(Config{ID: "simulated", ChainID: chainID, Native: native}), backend.Client())
	_, err := node.BuildTransfer(ctx, from.Hex(), "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF", native, eth(5))
	if !errors.Is(err, chain.ErrInsufficientFunds) || !strings.Contains(err.Error(), "ETH") {
		t.Fatalf("want insufficient funds, got %v", err)
	}

	// An RPC serving a different chain id must be refused.
	wrong := NewNode(New(Config{ID: "sepolia", ChainID: big.NewInt(11155111), Native: native}), backend.Client())
	if _, err := wrong.Balance(ctx, from.Hex(), native); err == nil || !strings.Contains(err.Error(), "serves chain id") {
		t.Fatalf("want chain id mismatch, got %v", err)
	}
}
