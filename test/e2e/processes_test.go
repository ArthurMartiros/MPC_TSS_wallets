// Package e2e runs ThresholdVault components as real OS processes:
// one vaultd coordinator and three signerd nodes.
package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"thresholdvault/internal/mpc"
	"thresholdvault/internal/signer"
	"thresholdvault/internal/store"
)

const (
	signerToken = "e2e-signer-token"
	apiToken    = "e2e-api-token"
)

type proc struct {
	name string
	cmd  *exec.Cmd
}

func build(t *testing.T, pkg string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), filepath.Base(pkg))
	cmd := exec.Command("go", "build", "-o", bin, pkg)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, out)
	}
	return bin
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// launch starts a process and waits until healthURL answers 200.
func launch(t *testing.T, name, bin string, args, env []string, healthURL string) *proc {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), name+".log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &proc{name: name, cmd: cmd}
	t.Cleanup(func() {
		p.stop()
		if t.Failed() {
			out, _ := os.ReadFile(logPath)
			t.Logf("--- %s log ---\n%s", name, out)
		}
	})
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, healthURL, nil)
		req.Header.Set("Authorization", "Bearer "+signerToken)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return p
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s did not become healthy", name)
	return nil
}

func (p *proc) stop() {
	if p.cmd.ProcessState != nil {
		return
	}
	_ = p.cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { _ = p.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		<-done
	}
}

type cluster struct {
	t         *testing.T
	signerBin string
	vaultURL  string
	peersDir  string
	addrs     map[string]string
	dataDirs  map[string]string
	procs     map[string]*proc
}

func (c *cluster) startSigner(name string) {
	c.procs[name] = launch(c.t, name, c.signerBin, []string{
		"--name", name, "--listen", c.addrs[name], "--data-dir", c.dataDirs[name],
		"--peers-dir", c.peersDir, "--relay-url", c.vaultURL, "--api-token", signerToken,
		"--policy", "dev-allow-all", "--preparams-pool", "0",
	}, []string{"SIGNER_PASSPHRASE=e2e-pass-" + name}, "http://"+c.addrs[name]+"/v1/health")
}

func (c *cluster) signerClient(name string) *signer.Client {
	return signer.NewClient("http://"+c.addrs[name], signerToken)
}

func startCluster(t *testing.T) *cluster {
	t.Helper()
	signerBin := build(t, "thresholdvault/cmd/signerd")
	vaultBin := build(t, "thresholdvault/cmd/vaultd")
	vaultAddr := freeAddr(t)
	c := &cluster{
		t: t, signerBin: signerBin, vaultURL: "http://" + vaultAddr, peersDir: t.TempDir(),
		addrs: map[string]string{}, dataDirs: map[string]string{}, procs: map[string]*proc{},
	}
	for _, name := range mpc.DefaultCommittee {
		c.addrs[name] = freeAddr(t)
		c.dataDirs[name] = t.TempDir()
	}
	c.procs["vaultd"] = launch(t, "vaultd", vaultBin, []string{
		"--listen", vaultAddr, "--db", filepath.Join(t.TempDir(), "vault.db"),
		"--api-token", apiToken, "--signer-token", signerToken,
		"--signer-user", "http://" + c.addrs["user"],
		"--signer-server", "http://" + c.addrs["server"],
		"--signer-backup", "http://" + c.addrs["backup"],
	}, nil, c.vaultURL+"/healthz")
	for _, name := range mpc.DefaultCommittee {
		c.startSigner(name)
	}
	return c
}

func (c *cluster) api(method, path string, body, out any) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.vaultURL+path, rd)
	req.Header.Set("Authorization", "Bearer "+apiToken)
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		c.t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			c.t.Fatal(err)
		}
	}
}

func parallel(names []string, fn func(name string) error) error {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for _, n := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(n); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("%s: %w", n, err))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

func TestProcessesKeygenAndSign(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns processes and generates fresh pre-parameters")
	}
	c := startCluster(t)

	t.Log("POST /wallets: DKG across 3 signer processes (fresh safe primes)...")
	var w store.Wallet
	c.api("POST", "/wallets", map[string]string{"name": "e2e"}, &w)
	raw, _ := hex.DecodeString(w.PublicKey)
	pub, err := ethcrypto.DecompressPubkey(raw)
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := w.AddressFor("ethereum-sepolia")
	if addr != ethcrypto.PubkeyToAddress(*pub).Hex() {
		t.Fatalf("address %s does not match public key", addr)
	}
	t.Logf("wallet %s, sepolia address %s", w.ID, addr)

	var listed []store.Wallet
	c.api("GET", "/wallets", nil, &listed)
	if len(listed) != 1 || listed[0].ID != w.ID {
		t.Fatalf("GET /wallets = %+v", listed)
	}

	// Signing is driven directly against the signers here; the transaction
	// endpoints exercise it through vaultd.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sign := func(session string, signers []string) {
		t.Helper()
		digest := sha256.Sum256([]byte(session))
		var (
			mu  sync.Mutex
			sig mpc.Signature
		)
		if err := parallel(signers, func(n string) error {
			res, err := c.signerClient(n).Sign(ctx, signer.SignRequest{SessionID: session, WalletID: w.ID, Signers: signers, Digest: hex.EncodeToString(digest[:])})
			if err != nil {
				return err
			}
			mu.Lock()
			sig = res.Signature
			mu.Unlock()
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := sig.Verify(pub, digest[:]); err != nil {
			t.Fatal(err)
		}
		t.Logf("%v signed and verified", signers)
	}
	sign("e2e-sign-1", []string{"user", "backup"})

	// Restart the server signer: its share reloads from the encrypted store
	// on disk and its pinned peer identities still match.
	c.procs["server"].stop()
	c.startSigner("server")
	sign("e2e-sign-2", []string{"user", "server"})
}
