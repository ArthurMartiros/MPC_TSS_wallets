package mpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"thresholdvault/internal/sharestore"
)

// Pre-parameters are expensive (safe primes), so tests cache them under
// testdata. They are TEST-ONLY fixtures; production signers generate fresh
// pre-parameters for every keygen.
func loadPreParams(t *testing.T, party string) *keygen.LocalPreParams {
	t.Helper()
	path := filepath.Join("testdata", "preparams-"+party+".json")
	if raw, err := os.ReadFile(path); err == nil {
		var p keygen.LocalPreParams
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		return &p
	}
	t.Logf("generating pre-parameters for %s (one-time, may take a few minutes)", party)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	p, err := GeneratePreParams(ctx)
	if err != nil {
		t.Fatalf("generate pre-params: %v", err)
	}
	raw, _ := json.Marshal(p)
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func runKeygen(t *testing.T) map[string]*KeyShare {
	t.Helper()
	pre := map[string]*keygen.LocalPreParams{}
	for _, p := range DefaultCommittee {
		pre[p] = loadPreParams(t, p)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	hub := NewMemoryHub(DefaultCommittee)
	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		shares = map[string]*KeyShare{}
		errs   []error
	)
	for _, p := range DefaultCommittee {
		wg.Add(1)
		go func() {
			defer wg.Done()
			share, err := Keygen(ctx, KeygenConfig{SessionID: "kg-test", Self: p, PreParams: pre[p]}, hub.Endpoint(p))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", p, err))
				cancel()
				return
			}
			shares[p] = share
		}()
	}
	wg.Wait()
	if len(errs) > 0 {
		t.Fatalf("keygen failed: %v", errors.Join(errs...))
	}
	return shares
}

var (
	sharedOnce   sync.Once
	sharedShares map[string]*KeyShare
)

// testShares runs one DKG and reuses it across tests to keep the suite fast.
func testShares(t *testing.T) map[string]*KeyShare {
	t.Helper()
	sharedOnce.Do(func() { sharedShares = runKeygen(t) })
	if sharedShares == nil {
		t.Fatal("shared keygen failed earlier")
	}
	return sharedShares
}

// runSign runs a signing session among signers, each signing its own digest
// (normally all the same).
func runSign(ctx context.Context, shares map[string]*KeyShare, signers []string, digests map[string][]byte) (map[string]*Signature, error) {
	hub := NewMemoryHub(signers)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		sigs = map[string]*Signature{}
		errs []error
	)
	for _, p := range signers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sig, err := Sign(ctx, SignConfig{SessionID: "sign-test", Signers: signers, Digest: digests[p]}, shares[p], hub.Endpoint(p))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", p, err))
				cancel()
				return
			}
			sigs[p] = sig
		}()
	}
	wg.Wait()
	return sigs, errors.Join(errs...)
}

func sameDigest(signers []string, d []byte) map[string][]byte {
	m := map[string][]byte{}
	for _, s := range signers {
		m[s] = d
	}
	return m
}

func TestKeygenProducesConsistentShares(t *testing.T) {
	shares := testShares(t)
	if len(shares) != 3 {
		t.Fatalf("want 3 shares, got %d", len(shares))
	}
	pub := shares[PartyUser].PublicKeyBytes()
	for name, s := range shares {
		if got := s.PublicKeyBytes(); string(got) != string(pub) {
			t.Errorf("%s has a different joint public key", name)
		}
		if err := s.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Secret shares must be distinct.
	if shares[PartyUser].Data.Xi.Cmp(shares[PartyServer].Data.Xi) == 0 {
		t.Error("user and server received identical secret shares")
	}
	t.Logf("joint public key: %x", pub)
	t.Logf("ethereum address: %s", ethcrypto.PubkeyToAddress(*shares[PartyUser].PublicKey()).Hex())
}

func TestEveryTwoOfThreeQuorumSigns(t *testing.T) {
	shares := testShares(t)
	quorums := [][]string{
		{PartyUser, PartyServer},
		{PartyUser, PartyBackup},
		{PartyServer, PartyBackup},
	}
	pub := shares[PartyUser].PublicKey()
	for _, q := range quorums {
		t.Run(q[0]+"+"+q[1], func(t *testing.T) {
			digest := sha256.Sum256([]byte("thresholdvault test " + q[0] + q[1]))
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			sigs, err := runSign(ctx, shares, q, sameDigest(q, digest[:]))
			if err != nil {
				t.Fatal(err)
			}
			a, b := sigs[q[0]], sigs[q[1]]
			if a.R != b.R || a.S != b.S || a.V != b.V {
				t.Fatal("parties produced different signatures")
			}
			if err := a.Verify(pub, digest[:]); err != nil {
				t.Fatal(err)
			}
			// Independent check through go-ethereum's recovery path.
			recovered, err := ethcrypto.SigToPub(digest[:], a.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if ethcrypto.PubkeyToAddress(*recovered) != ethcrypto.PubkeyToAddress(*pub) {
				t.Fatal("recovered address differs from wallet address")
			}
			// Low-S is required by Ethereum (EIP-2) and Bitcoin (BIP-62/146).
			halfN := new(big.Int).Rsh(ethcrypto.S256().Params().N, 1)
			if new(big.Int).SetBytes(a.S[:]).Cmp(halfN) > 0 {
				t.Fatal("signature is not low-S")
			}
		})
	}
}

func TestDigestWithLeadingZeroBytes(t *testing.T) {
	shares := testShares(t)
	digest := make([]byte, 32)
	digest[3] = 0x01 // 0x000000 01 ...
	if _, err := rand.Read(digest[4:]); err != nil {
		t.Fatal(err)
	}
	signers := []string{PartyUser, PartyServer}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	sigs, err := runSign(ctx, shares, signers, sameDigest(signers, digest))
	if err != nil {
		t.Fatal(err)
	}
	if err := sigs[PartyUser].Verify(shares[PartyUser].PublicKey(), digest); err != nil {
		t.Fatal(err)
	}
}

// TestSingleShareCannotSign demonstrates, in several independent ways, that
// one share on its own is not the wallet key and can't produce a signature.
func TestSingleShareCannotSign(t *testing.T) {
	shares := testShares(t)
	pub := shares[PartyUser].PublicKey()
	digest := sha256.Sum256([]byte("unauthorised transfer"))

	t.Run("quorum is enforced", func(t *testing.T) {
		_, err := Sign(context.Background(), SignConfig{SessionID: "solo", Signers: []string{PartyUser}, Digest: digest[:]}, shares[PartyUser], NewMemoryHub([]string{PartyUser}).Endpoint(PartyUser))
		if !errors.Is(err, ErrInsufficientQuorum) {
			t.Fatalf("want ErrInsufficientQuorum, got %v", err)
		}
	})

	t.Run("share is not the private key", func(t *testing.T) {
		for name, s := range shares {
			if crypto.ScalarBaseMult(tss.S256(), s.Data.Xi).Equals(s.Data.ECDSAPub) {
				t.Fatalf("%s's share alone equals the wallet key", name)
			}
		}
	})

	t.Run("signing with a raw share fails verification", func(t *testing.T) {
		for name, s := range shares {
			priv := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: tss.S256()}, D: s.Data.Xi}
			priv.PublicKey.X, priv.PublicKey.Y = tss.S256().ScalarBaseMult(s.Data.Xi.Bytes())
			r, sv, err := ecdsa.Sign(rand.Reader, priv, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			if ecdsa.Verify(pub, digest[:], r, sv) {
				t.Fatalf("signature made with only %s's share verified against the wallet key", name)
			}
		}
	})

	t.Run("protocol can't complete when the peer is absent", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		hub := NewMemoryHub([]string{PartyUser, PartyServer})
		_, err := Sign(ctx, SignConfig{SessionID: "absent-peer", Signers: []string{PartyUser, PartyServer}, Digest: digest[:]}, shares[PartyUser], hub.Endpoint(PartyUser))
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("want deadline exceeded, got %v", err)
		}
	})
}

func TestSignersMustAgreeOnDigest(t *testing.T) {
	shares := testShares(t)
	signers := []string{PartyUser, PartyServer}
	d1 := sha256.Sum256([]byte("pay alice 1 ETH"))
	d2 := sha256.Sum256([]byte("pay mallory 100 ETH"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := runSign(ctx, shares, signers, map[string][]byte{PartyUser: d1[:], PartyServer: d2[:]})
	if err == nil {
		t.Fatal("signing succeeded although parties signed different digests")
	}
	t.Logf("rejected as expected: %v", err)
}

func TestLocalPartyMustBeASigner(t *testing.T) {
	shares := testShares(t)
	digest := sha256.Sum256([]byte("x"))
	_, err := Sign(context.Background(), SignConfig{SessionID: "s", Signers: []string{PartyServer, PartyBackup}, Digest: digest[:]}, shares[PartyUser], NewMemoryHub(nil).Endpoint(PartyUser))
	if !errors.Is(err, ErrNotInSession) {
		t.Fatalf("want ErrNotInSession, got %v", err)
	}
}

func TestRejectsBadInputs(t *testing.T) {
	shares := testShares(t)
	tr := NewMemoryHub(nil).Endpoint(PartyUser)
	ctx := context.Background()
	if _, err := Sign(ctx, SignConfig{SessionID: "s", Signers: []string{PartyUser, PartyServer}, Digest: []byte("short")}, shares[PartyUser], tr); err == nil {
		t.Error("accepted a non-32-byte digest")
	}
	d := sha256.Sum256(nil)
	if _, err := Sign(ctx, SignConfig{SessionID: "s", Signers: []string{PartyUser, "mallory"}, Digest: d[:]}, shares[PartyUser], tr); !errors.Is(err, ErrUnknownParty) {
		t.Errorf("want ErrUnknownParty, got %v", err)
	}
	if _, err := Keygen(ctx, KeygenConfig{SessionID: "k", Self: PartyUser}, tr); err == nil {
		t.Error("keygen accepted missing pre-parameters")
	}
}

func TestTamperedShareIsRejected(t *testing.T) {
	shares := testShares(t)
	raw, err := shares[PartyServer].Marshal()
	if err != nil {
		t.Fatal(err)
	}
	tampered, err := UnmarshalKeyShare(raw)
	if err != nil {
		t.Fatal(err)
	}
	tampered.Data.Xi = new(big.Int).Add(tampered.Data.Xi, big.NewInt(1))
	if err := tampered.Validate(); err == nil {
		t.Fatal("share with modified Xi passed validation")
	}
}

// TestSharesSurviveEncryptedStorage stores each share in its own encrypted
// store (as three separate signer processes would) and signs with the
// reloaded copies.
func TestSharesSurviveEncryptedStorage(t *testing.T) {
	shares := testShares(t)
	cheap := sharestore.KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1}
	reloaded := map[string]*KeyShare{}
	for name, s := range shares {
		store, err := sharestore.OpenWithKDF(t.TempDir(), []byte("passphrase-"+name), cheap)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := s.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Put("share/wallet-1", raw); err != nil {
			t.Fatal(err)
		}
		back, err := store.Get("share/wallet-1")
		if err != nil {
			t.Fatal(err)
		}
		if reloaded[name], err = UnmarshalKeyShare(back); err != nil {
			t.Fatal(err)
		}
	}
	signers := []string{PartyServer, PartyBackup}
	digest := sha256.Sum256([]byte("after reload"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	sigs, err := runSign(ctx, reloaded, signers, sameDigest(signers, digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	if err := sigs[PartyServer].Verify(shares[PartyUser].PublicKey(), digest[:]); err != nil {
		t.Fatal(err)
	}
}
