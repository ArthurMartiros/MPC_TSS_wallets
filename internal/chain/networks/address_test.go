package networks

import (
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"thresholdvault/internal/chain/tron"
	"thresholdvault/internal/chain/utxo"
)

// keyOne returns the public key for private key 1 (= the generator G), the
// key behind many published address test vectors. It is computed directly;
// no MPC involved.
func keyOne(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	k, err := ethcrypto.ToECDSA(common32(1))
	if err != nil {
		t.Fatal(err)
	}
	return &k.PublicKey
}

func common32(v int64) []byte {
	b := make([]byte, 32)
	big.NewInt(v).FillBytes(b)
	return b
}

func TestAddressVectors(t *testing.T) {
	pub := keyOne(t)
	reg := Default(RPC{})
	cases := []struct{ chain, want string }{
		// Well-known Ethereum address of private key 1.
		{EthereumSepolia, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"},
		{BSCTestnet, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"},
		// BIP-173 test vector (P2WPKH of G, testnet).
		{BitcoinTestnet, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"},
	}
	for _, tc := range cases {
		c, err := reg.Get(tc.chain)
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.Address(pub)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("%s: got %s want %s", tc.chain, got, tc.want)
		}
		if err := c.ValidateAddress(got); err != nil {
			t.Errorf("%s: own address fails validation: %v", tc.chain, err)
		}
	}
}

func TestBitcoinMainnetVectors(t *testing.T) {
	pub := keyOne(t)
	if got := hex.EncodeToString(utxo.PubKeyHash(pub)); got != "751e76e8199196d454941c45d1b3a323f1433bd6" {
		t.Fatalf("hash160 = %s", got)
	}
	btc := utxo.New(utxo.BitcoinMainnet)
	if got, _ := btc.Address(pub); got != "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" {
		t.Errorf("BIP-173 mainnet vector: got %s", got)
	}
	p2pkh := utxo.New(utxo.Params{ID: "btc-p2pkh", AddressType: utxo.P2PKH, PubKeyHash: 0x00})
	if got, _ := p2pkh.Address(pub); got != "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH" {
		t.Errorf("P2PKH mainnet vector: got %s", got)
	}
}

func TestLitecoinAndDashEncodings(t *testing.T) {
	pub := keyOne(t)
	reg := Default(RPC{})
	h160 := utxo.PubKeyHash(pub)

	ltc, _ := reg.Get(LitecoinTestnet)
	ltcAddr, _ := ltc.Address(pub)
	if !strings.HasPrefix(ltcAddr, "tltc1q") {
		t.Errorf("litecoin testnet address %s lacks tltc1q prefix", ltcAddr)
	}
	dec, err := ltc.(*utxo.Chain).DecodeAddress(ltcAddr)
	if err != nil || hex.EncodeToString(dec.Hash) != hex.EncodeToString(h160) {
		t.Errorf("litecoin round trip failed: %v", err)
	}

	dash, _ := reg.Get(DashTestnet)
	dashAddr, _ := dash.Address(pub)
	if !strings.HasPrefix(dashAddr, "y") {
		t.Errorf("dash testnet address %s should start with y", dashAddr)
	}
	dashMain, _ := utxo.New(utxo.DashMainnet).Address(pub)
	if !strings.HasPrefix(dashMain, "X") {
		t.Errorf("dash mainnet address %s should start with X", dashMain)
	}
	dd, err := dash.(*utxo.Chain).DecodeAddress(dashAddr)
	if err != nil || dd.Type != utxo.P2PKH || hex.EncodeToString(dd.Hash) != hex.EncodeToString(h160) {
		t.Errorf("dash round trip failed: %v", err)
	}
}

func TestCrossNetworkAddressesRejected(t *testing.T) {
	pub := keyOne(t)
	reg := Default(RPC{})
	addrs := map[string]string{}
	for _, c := range reg.All() {
		a, err := c.Address(pub)
		if err != nil {
			t.Fatal(err)
		}
		addrs[c.ID()] = a
	}
	// The two EVM chains intentionally share addresses; everything else must
	// reject foreign addresses.
	for _, c := range reg.All() {
		for id, a := range addrs {
			if id == c.ID() || (c.Family() == "evm" && strings.HasPrefix(a, "0x")) {
				continue
			}
			if c.ValidateAddress(a) == nil {
				t.Errorf("%s accepted %s address %s", c.ID(), id, a)
			}
		}
	}
	btc, _ := reg.Get(BitcoinTestnet)
	if btc.ValidateAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == nil {
		t.Error("bitcoin testnet accepted a mainnet address")
	}
}

func TestTronVectors(t *testing.T) {
	// From the TRON developer docs (account address formats).
	h, _ := hex.DecodeString("8840E6C55B9ADA326D211D818C34A994AECED808")
	if got := tron.EncodeAddress(h); got != "TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL" {
		t.Errorf("tron encode: got %s", got)
	}
	back, err := tron.DecodeAddress("TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL")
	if err != nil || !strings.EqualFold(hex.EncodeToString(back), "8840E6C55B9ADA326D211D818C34A994AECED808") {
		t.Errorf("tron decode: %x %v", back, err)
	}
	// A TRON address is the same 20-byte account hash as the EVM address.
	reg := Default(RPC{})
	trx, _ := reg.Get(TronNile)
	addr, _ := trx.Address(keyOne(t))
	h20, _ := tron.DecodeAddress(addr)
	if "0x"+hex.EncodeToString(h20) != strings.ToLower("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf") {
		t.Errorf("tron address %s does not match the EVM account hash", addr)
	}
	if !strings.HasPrefix(addr, "T") {
		t.Errorf("tron address %s should start with T", addr)
	}
}

func TestEVMChecksumValidation(t *testing.T) {
	reg := Default(RPC{})
	eth, _ := reg.Get(EthereumSepolia)
	good := "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
	for _, ok := range []string{good, strings.ToLower(good), "0x" + strings.ToUpper(good[2:])} {
		if err := eth.ValidateAddress(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"0x7e5F4552091A69125d5DfCb7b8C2659029395Bdf", // checksum broken
		"7E5F4552091A69125d5DfCb7b8C2659029395Bdf",   // no prefix
		"0x7E5F4552091A69125d5DfCb7b8C2659029395B",   // short
		"0x0000000000000000000000000000000000000000", // zero address
	} {
		if err := eth.ValidateAddress(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
