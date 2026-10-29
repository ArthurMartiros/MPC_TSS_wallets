package coordinator

import (
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"thresholdvault/internal/chain/networks"
	"thresholdvault/internal/signer"
	"thresholdvault/internal/store"
)

// fakeSigner returns canned keygen results so failure handling can be tested
// without running MPC.
type fakeSigner struct {
	name string
	pub  string
	err  error
}

func (f *fakeSigner) Identity(context.Context) (*signer.IdentityResponse, error) {
	return &signer.IdentityResponse{Name: f.name, Fingerprint: "fp"}, f.err
}
func (f *fakeSigner) Health(context.Context) (*signer.HealthResponse, error) {
	return &signer.HealthResponse{Name: f.name}, f.err
}
func (f *fakeSigner) Keygen(_ context.Context, req signer.KeygenRequest) (*signer.KeygenResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &signer.KeygenResult{WalletID: req.WalletID, Party: f.name, PublicKey: f.pub}, nil
}
func (f *fakeSigner) Sign(context.Context, signer.SignRequest) (*signer.SignResult, error) {
	return nil, errors.New("not implemented")
}

func pubHex(seed byte) string {
	k, _ := ethcrypto.ToECDSA(append(make([]byte, 31), seed))
	return hex.EncodeToString(ethcrypto.CompressPubkey(&k.PublicKey))
}

func newCoord(t *testing.T, signers map[string]SignerAPI) (*Coordinator, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	c, err := New(Config{Store: st, Chains: networks.Default(networks.RPC{}), Signers: signers})
	if err != nil {
		t.Fatal(err)
	}
	return c, st
}

func TestCreateWalletFailures(t *testing.T) {
	ctx := context.Background()
	cases := map[string]map[string]SignerAPI{
		"backup offline": {
			"user":   &fakeSigner{name: "user", pub: pubHex(1)},
			"server": &fakeSigner{name: "server", pub: pubHex(1)},
			"backup": &fakeSigner{name: "backup", err: errors.New("connection refused")},
		},
		"public keys disagree": {
			"user":   &fakeSigner{name: "user", pub: pubHex(1)},
			"server": &fakeSigner{name: "server", pub: pubHex(2)},
			"backup": &fakeSigner{name: "backup", pub: pubHex(1)},
		},
		"invalid public key": {
			"user":   &fakeSigner{name: "user", pub: "02ff"},
			"server": &fakeSigner{name: "server", pub: "02ff"},
			"backup": &fakeSigner{name: "backup", pub: "02ff"},
		},
	}
	for name, signers := range cases {
		t.Run(name, func(t *testing.T) {
			c, st := newCoord(t, signers)
			if _, err := c.CreateWallet(ctx, "w"); err == nil {
				t.Fatal("expected failure")
			}
			if ws, _ := st.ListWallets(ctx); len(ws) != 0 {
				t.Fatal("wallet stored despite failure")
			}
		})
	}
}

func TestNewRequiresAllSigners(t *testing.T) {
	if _, err := New(Config{Signers: map[string]SignerAPI{"user": &fakeSigner{}}}); err == nil {
		t.Fatal("accepted incomplete signer set")
	}
}
