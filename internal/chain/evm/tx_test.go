package evm

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"thresholdvault/internal/chain"
)

const erc20ABI = `[
 {"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"type":"bool"}]},
 {"type":"function","name":"balanceOf","inputs":[{"name":"a","type":"address"}],"outputs":[{"type":"uint256"}]},
 {"type":"function","name":"decimals","inputs":[],"outputs":[{"type":"uint8"}]},
 {"type":"function","name":"symbol","inputs":[],"outputs":[{"type":"string"}]}
]`

var testToken = chain.Asset{Symbol: "TKN", Decimals: 6, Contract: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", Standard: "erc20"}

func testChain() *Chain {
	return New(Config{
		ID: "test-evm", Name: "Test", ChainID: big.NewInt(11155111),
		Native: chain.Asset{Symbol: "ETH", Decimals: 18, Standard: "native"},
		Tokens: []chain.Asset{testToken},
	})
}

func TestSelectorsMatchABI(t *testing.T) {
	parsed, err := abi.JSON(strings.NewReader(erc20ABI))
	if err != nil {
		t.Fatal(err)
	}
	for name, sel := range map[string][]byte{
		"transfer": selectorTransfer, "balanceOf": selectorBalanceOf,
		"decimals": selectorDecimals, "symbol": selectorSymbol,
	} {
		if !bytes.Equal(parsed.Methods[name].ID, sel) {
			t.Errorf("%s selector %x, abi says %x", name, sel, parsed.Methods[name].ID)
		}
	}
}

func TestEncodeTransferMatchesABI(t *testing.T) {
	parsed, _ := abi.JSON(strings.NewReader(erc20ABI))
	to := common.HexToAddress("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf")
	amount, _ := new(big.Int).SetString("1500000", 10)
	want, err := parsed.Pack("transfer", to, amount)
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeTransfer(to, amount)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("calldata mismatch\n got %x\nwant %x", got, want)
	}
	gotTo, gotAmount, err := DecodeTransfer(got)
	if err != nil || gotTo != to || gotAmount.Cmp(amount) != 0 {
		t.Fatalf("decode: %v %v %v", gotTo, gotAmount, err)
	}
	// Dirty address padding must be rejected.
	bad := append([]byte{}, got...)
	bad[5] = 1
	if _, _, err := DecodeTransfer(bad); err == nil {
		t.Error("accepted dirty address padding")
	}
	if _, _, err := DecodeTransfer(got[:67]); err == nil {
		t.Error("accepted truncated calldata")
	}
	if _, err := EncodeTransfer(to, big.NewInt(0)); err == nil {
		t.Error("encoded a zero transfer")
	}
}

func rawTx(t *testing.T, c *Chain, mutate func(*types.DynamicFeeTx)) []byte {
	t.Helper()
	to := common.HexToAddress("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf")
	inner := &types.DynamicFeeTx{
		ChainID: c.ChainID(), Nonce: 7, GasTipCap: big.NewInt(1_000_000_000), GasFeeCap: big.NewInt(30_000_000_000),
		Gas: 21000, To: &to, Value: big.NewInt(10_000_000_000_000_000),
	}
	if mutate != nil {
		mutate(inner)
	}
	raw, err := types.NewTx(inner).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDecodeNativeTransfer(t *testing.T) {
	c := testChain()
	s, err := c.DecodeUnsigned(rawTx(t, c, nil))
	if err != nil {
		t.Fatal(err)
	}
	if s.Asset != "ETH" || s.AmountDisplay != "0.01 ETH" || s.Nonce != 7 || s.Contract != "" {
		t.Fatalf("summary %+v", s)
	}
	if s.To != "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf" {
		t.Fatalf("to = %s", s.To)
	}
	// max fee = 21000 gas × 30 gwei = 0.00063 ETH
	if s.MaxFeeDisplay != "0.00063 ETH" {
		t.Fatalf("max fee = %s", s.MaxFeeDisplay)
	}
	tx := new(types.Transaction)
	_ = tx.UnmarshalBinary(rawTx(t, c, nil))
	if s.Sighash != hex.EncodeToString(types.LatestSignerForChainID(c.ChainID()).Hash(tx).Bytes()) {
		t.Fatal("sighash differs from go-ethereum's signer hash")
	}
}

func TestDecodeTokenTransfer(t *testing.T) {
	c := testChain()
	contract := common.HexToAddress(testToken.Contract)
	recipient := common.HexToAddress("0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF")
	data, _ := EncodeTransfer(recipient, big.NewInt(2_500_000))
	s, err := c.DecodeUnsigned(rawTx(t, c, func(tx *types.DynamicFeeTx) {
		tx.To, tx.Value, tx.Data, tx.Gas = &contract, new(big.Int), data, 65000
	}))
	if err != nil {
		t.Fatal(err)
	}
	if s.Asset != "TKN" || s.AmountDisplay != "2.5 TKN" || s.To != recipient.Hex() || !strings.EqualFold(s.Contract, testToken.Contract) {
		t.Fatalf("summary %+v", s)
	}
}

func TestDecodeRejects(t *testing.T) {
	c := testChain()
	unknown := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	data, _ := EncodeTransfer(unknown, big.NewInt(1))
	contract := common.HexToAddress(testToken.Contract)
	cases := map[string][]byte{
		"wrong chain id":    rawTx(t, c, func(tx *types.DynamicFeeTx) { tx.ChainID = big.NewInt(1) }),
		"contract creation": rawTx(t, c, func(tx *types.DynamicFeeTx) { tx.To = nil }),
		"zero value":        rawTx(t, c, func(tx *types.DynamicFeeTx) { tx.Value = new(big.Int) }),
		"arbitrary calldata": rawTx(t, c, func(tx *types.DynamicFeeTx) {
			tx.Data = []byte{0xde, 0xad, 0xbe, 0xef}
			tx.Value = new(big.Int)
		}),
		"unknown token contract": rawTx(t, c, func(tx *types.DynamicFeeTx) { tx.To, tx.Value, tx.Data = &unknown, new(big.Int), data }),
		"token with value":       rawTx(t, c, func(tx *types.DynamicFeeTx) { tx.To, tx.Data = &contract, data }),
		"tip above fee cap":      rawTx(t, c, func(tx *types.DynamicFeeTx) { tx.GasTipCap = big.NewInt(40_000_000_000) }),
		"already signed":         rawTx(t, c, func(tx *types.DynamicFeeTx) { tx.V, tx.R, tx.S = big.NewInt(1), big.NewInt(2), big.NewInt(3) }),
		"access list": rawTx(t, c, func(tx *types.DynamicFeeTx) {
			tx.AccessList = types.AccessList{{Address: unknown}}
		}),
		"garbage": {0x02, 0x01, 0x02},
	}
	legacy, _ := types.NewTx(&types.LegacyTx{Nonce: 1, Gas: 21000, GasPrice: big.NewInt(1), To: &unknown, Value: big.NewInt(1)}).MarshalBinary()
	cases["legacy transaction"] = legacy
	for name, raw := range cases {
		if _, err := c.DecodeUnsigned(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestApplySignature(t *testing.T) {
	c := testChain()
	key, _ := ethcrypto.GenerateKey()
	from := ethcrypto.PubkeyToAddress(key.PublicKey).Hex()
	raw := rawTx(t, c, nil)
	s, _ := c.DecodeUnsigned(raw)
	digest, _ := hex.DecodeString(s.Sighash)
	sig, err := ethcrypto.Sign(digest, key) // ordinary key; MPC is tested elsewhere
	if err != nil {
		t.Fatal(err)
	}
	signed, hash, err := c.ApplySignature(raw, sig, from)
	if err != nil {
		t.Fatal(err)
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(signed); err != nil || tx.Hash().Hex() != hash {
		t.Fatalf("signed tx: %v", err)
	}
	other, _ := ethcrypto.GenerateKey()
	if _, _, err := c.ApplySignature(raw, sig, ethcrypto.PubkeyToAddress(other.PublicKey).Hex()); err == nil {
		t.Fatal("accepted a signature from a different key")
	}
	if _, _, err := c.ApplySignature(raw, sig[:64], from); err == nil {
		t.Fatal("accepted a 64-byte signature")
	}
}
