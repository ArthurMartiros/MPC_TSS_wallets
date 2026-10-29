package signer

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"thresholdvault/internal/chain"
	"thresholdvault/internal/chain/evm"
	"thresholdvault/internal/chain/networks"
	"thresholdvault/internal/sharestore"
)

// realPolicies wires the production policies: UserPolicy for the user
// signer, CosignerPolicy for server and backup.
func realPolicies(name string, store *sharestore.Store, peers PeerResolver) Authorizer {
	chains := networks.Default(networks.RPC{})
	if name == "user" {
		return &UserPolicy{Store: store, Chains: chains}
	}
	return &CosignerPolicy{Peers: peers, Chains: chains}
}

// sepoliaTx returns an unsigned Sepolia transfer (hex) and its sighash.
func sepoliaTx(t *testing.T, wei int64, nonce uint64) (string, string) {
	t.Helper()
	c, _ := networks.Default(networks.RPC{}).Get(networks.EthereumSepolia)
	ec := c.(*evm.Chain)
	to := common.HexToAddress("0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF")
	tx, err := ec.NewTransferTx(to, ec.Assets()[0], big.NewInt(wei), nonce, 21000, big.NewInt(1e9), big.NewInt(30e9))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	s, err := ec.DecodeUnsigned(raw)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw), s.Sighash
}

// signTx runs a signing session with the given request on every signer.
func (c *cluster) signTx(ctx context.Context, req SignRequest) (map[string]*SignResult, map[string]error) {
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		out  = map[string]*SignResult{}
		errs = map[string]error{}
	)
	for _, name := range req.Signers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := c.nodes[name].client.Sign(ctx, req)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs[name] = err
				return
			}
			out[name] = res
		}()
	}
	wg.Wait()
	return out, errs
}

func (c *cluster) approve(t *testing.T, txID, walletID, txHex string) (*ReviewResponse, string) {
	t.Helper()
	ctx := context.Background()
	rev, err := c.nodes["user"].approvals.Review(ctx, ReviewRequest{TxID: txID, WalletID: walletID, Chain: networks.EthereumSepolia, Transaction: txHex})
	if err != nil {
		t.Fatal(err)
	}
	conf, err := c.nodes["user"].approvals.Confirm(ctx, ConfirmRequest{TxID: txID, Sighash: rev.Summary.Sighash})
	if err != nil {
		t.Fatal(err)
	}
	return rev, conf.Approval
}

func TestApprovedTransactionIsSigned(t *testing.T) {
	c := newCluster(t, realPolicies)
	pubHex := c.keygen(t, "w")
	raw, _ := hex.DecodeString(pubHex)
	pub, _ := ethcrypto.DecompressPubkey(raw)
	wallet := ethcrypto.PubkeyToAddress(*pub).Hex()

	txHex, sighash := sepoliaTx(t, 1e16, 0)
	rev, tok := c.approve(t, "tx_1", "w", txHex)
	// The user signer's independent reading of the transaction.
	if rev.From != wallet || rev.Summary.AmountDisplay != "0.01 ETH" || rev.Summary.To != "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF" || rev.Summary.Sighash != sighash {
		t.Fatalf("review %+v / %+v", rev, rev.Summary)
	}

	for _, signers := range [][]string{{"user", "server"}, {"server", "backup"}} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		res, errs := c.signTx(ctx, SignRequest{
			SessionID: "s-" + signers[0] + signers[1], WalletID: "w", Signers: signers, Digest: sighash,
			Chain: networks.EthereumSepolia, Transaction: txHex, TxID: "tx_1", Approval: tok,
		})
		cancel()
		if len(errs) > 0 {
			t.Fatalf("%v: %v", signers, errs)
		}
		// The threshold signature produces a valid transaction from the wallet.
		ch, _ := networks.Default(networks.RPC{}).Get(networks.EthereumSepolia)
		txRaw, _ := hex.DecodeString(txHex)
		if _, _, err := ch.(chain.TxCodec).ApplySignature(txRaw, res[signers[0]].Signature.Bytes(), wallet); err != nil {
			t.Fatalf("%v: %v", signers, err)
		}
	}
}

func TestPoliciesRefuseUnapprovedOrAlteredTransactions(t *testing.T) {
	c := newCluster(t, realPolicies)
	c.keygen(t, "w")
	txHex, sighash := sepoliaTx(t, 1e16, 0)
	_, tok := c.approve(t, "tx_ok", "w", txHex)
	evilHex, evilSighash := sepoliaTx(t, 9e17, 0) // 0.9 ETH instead of 0.01

	cases := map[string]SignRequest{
		"no approval at all":              {TxID: "tx_none", Transaction: txHex, Digest: sighash},
		"contents swapped after approval": {TxID: "tx_ok", Transaction: evilHex, Digest: evilSighash, Approval: tok},
		"digest not of the transaction":   {TxID: "tx_ok", Transaction: txHex, Digest: evilSighash, Approval: tok},
		"bare digest, no transaction":     {TxID: "tx_ok", Digest: sighash, Approval: tok},
	}
	i := 0
	for name, req := range cases {
		i++
		t.Run(name, func(t *testing.T) {
			req.WalletID, req.Chain = "w", networks.EthereumSepolia
			for _, signer := range []string{"user", "server", "backup"} {
				req.SessionID = fmt.Sprintf("refuse-%d-%s", i, signer)
				req.Signers = []string{"user", signer}
				if signer == "user" {
					req.Signers = []string{"user", "server"}
				}
				_, err := c.nodes[signer].client.Sign(context.Background(), req)
				if !isStatus(err, http.StatusForbidden) {
					t.Errorf("%s: want 403, got %v", signer, err)
				}
			}
		})
	}
}

func TestConfirmRequiresMatchingReview(t *testing.T) {
	c := newCluster(t, realPolicies)
	c.keygen(t, "w")
	ctx := context.Background()
	user := c.nodes["user"].approvals
	if _, err := user.Confirm(ctx, ConfirmRequest{TxID: "tx_x", Sighash: "00"}); !isStatus(err, http.StatusBadRequest) {
		t.Fatalf("confirm without review: %v", err)
	}
	txHex, _ := sepoliaTx(t, 1e16, 0)
	if _, err := user.Review(ctx, ReviewRequest{TxID: "tx_y", WalletID: "w", Chain: networks.EthereumSepolia, Transaction: txHex}); err != nil {
		t.Fatal(err)
	}
	if _, err := user.Confirm(ctx, ConfirmRequest{TxID: "tx_y", Sighash: "deadbeef"}); !isStatus(err, http.StatusBadRequest) {
		t.Fatalf("confirm with wrong sighash: %v", err)
	}
	// Garbage and unknown wallets are refused at review time.
	if _, err := user.Review(ctx, ReviewRequest{TxID: "tx_z", WalletID: "w", Chain: networks.EthereumSepolia, Transaction: "02ff"}); !isStatus(err, http.StatusBadRequest) {
		t.Fatalf("review garbage: %v", err)
	}
	if _, err := user.Review(ctx, ReviewRequest{TxID: "tx_z", WalletID: "nope", Chain: networks.EthereumSepolia, Transaction: txHex}); !isStatus(err, http.StatusNotFound) {
		t.Fatalf("review unknown wallet: %v", err)
	}
}

func TestCoordinatorTokenCannotApprove(t *testing.T) {
	c := newCluster(t, realPolicies)
	// The coordinator only knows the signer API token.
	asCoordinator := *c.nodes["user"].approvals
	asCoordinator.Token = testToken
	_, err := asCoordinator.Review(context.Background(), ReviewRequest{TxID: "tx_1", WalletID: "w", Chain: networks.EthereumSepolia, Transaction: "00"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		t.Fatalf("want 401, got %v", err)
	}
}
