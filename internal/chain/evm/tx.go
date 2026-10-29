package evm

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"thresholdvault/internal/chain"
)

// ERC-20 / BEP-20 function selectors (first 4 bytes of keccak256 of the
// signature). Verified against go-ethereum's ABI encoder in tests.
var (
	selectorTransfer  = []byte{0xa9, 0x05, 0x9c, 0xbb} // transfer(address,uint256)
	selectorBalanceOf = []byte{0x70, 0xa0, 0x82, 0x31} // balanceOf(address)
	selectorDecimals  = []byte{0x31, 0x3c, 0xe5, 0x67} // decimals()
	selectorSymbol    = []byte{0x95, 0xd8, 0x9b, 0x41} // symbol()
)

var maxUint256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

// EncodeTransfer returns calldata for transfer(to, amount).
func EncodeTransfer(to common.Address, amount *big.Int) ([]byte, error) {
	if amount.Sign() <= 0 || amount.Cmp(maxUint256) > 0 {
		return nil, errors.New("evm: token amount out of range")
	}
	data := make([]byte, 0, 68)
	data = append(data, selectorTransfer...)
	data = append(data, common.LeftPadBytes(to.Bytes(), 32)...)
	return append(data, common.LeftPadBytes(amount.Bytes(), 32)...), nil
}

// DecodeTransfer parses transfer(to, amount) calldata strictly: exact length
// and zero padding on the address word.
func DecodeTransfer(data []byte) (common.Address, *big.Int, error) {
	if len(data) != 68 || !bytes.Equal(data[:4], selectorTransfer) {
		return common.Address{}, nil, errors.New("evm: calldata is not an ERC-20 transfer(address,uint256)")
	}
	if !bytes.Equal(data[4:16], make([]byte, 12)) {
		return common.Address{}, nil, errors.New("evm: malformed transfer recipient")
	}
	return common.BytesToAddress(data[16:36]), new(big.Int).SetBytes(data[36:68]), nil
}

func (c *Chain) signer() types.Signer { return types.LatestSignerForChainID(c.cfg.ChainID) }

// tokenByContract finds a configured token by contract address.
func (c *Chain) tokenByContract(addr common.Address) (chain.Asset, bool) {
	for _, t := range c.cfg.Tokens {
		if strings.EqualFold(t.Contract, addr.Hex()) {
			return t, true
		}
	}
	return chain.Asset{}, false
}

// NewTransferTx builds an unsigned EIP-1559 transaction for a native or
// token transfer.
func (c *Chain) NewTransferTx(to common.Address, asset chain.Asset, amount *big.Int, nonce, gas uint64, tipCap, feeCap *big.Int) (*types.Transaction, error) {
	inner := &types.DynamicFeeTx{
		ChainID:   c.ChainID(),
		Nonce:     nonce,
		GasTipCap: tipCap,
		GasFeeCap: feeCap,
		Gas:       gas,
	}
	if asset.IsNative() {
		inner.To, inner.Value = &to, amount
	} else {
		contract, err := ParseAddress(asset.Contract)
		if err != nil {
			return nil, err
		}
		data, err := EncodeTransfer(to, amount)
		if err != nil {
			return nil, err
		}
		inner.To, inner.Value, inner.Data = &contract, new(big.Int), data
	}
	return types.NewTx(inner), nil
}

// decode parses raw bytes into an unsigned EIP-1559 transaction for this
// chain, rejecting anything else.
func (c *Chain) decode(raw []byte) (*types.Transaction, error) {
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("evm: decode transaction: %w", err)
	}
	// Reject non-canonical encodings so the bytes reviewed are exactly the
	// bytes signed.
	if again, err := tx.MarshalBinary(); err != nil || !bytes.Equal(again, raw) {
		return nil, errors.New("evm: non-canonical transaction encoding")
	}
	if tx.Type() != types.DynamicFeeTxType {
		return nil, fmt.Errorf("evm: only EIP-1559 transactions are supported, got type %d", tx.Type())
	}
	if tx.ChainId().Cmp(c.cfg.ChainID) != 0 {
		return nil, fmt.Errorf("evm: transaction is for chain id %s, expected %s (%s)", tx.ChainId(), c.cfg.ChainID, c.cfg.ID)
	}
	if v, r, s := tx.RawSignatureValues(); v.Sign() != 0 || r.Sign() != 0 || s.Sign() != 0 {
		return nil, errors.New("evm: transaction is already signed")
	}
	if tx.To() == nil {
		return nil, errors.New("evm: contract creation is not allowed")
	}
	if tx.Gas() == 0 || tx.GasFeeCap().Sign() <= 0 || tx.GasFeeCap().Cmp(tx.GasTipCap()) < 0 {
		return nil, errors.New("evm: invalid gas parameters")
	}
	if len(tx.AccessList()) > 0 {
		return nil, errors.New("evm: access lists are not supported")
	}
	return tx, nil
}

// DecodeUnsigned implements chain.TxCodec. Only plain native transfers and
// transfers of configured tokens are accepted.
func (c *Chain) DecodeUnsigned(raw []byte) (*chain.Summary, error) {
	tx, err := c.decode(raw)
	if err != nil {
		return nil, err
	}
	native := c.cfg.Native
	maxFee := new(big.Int).Mul(new(big.Int).SetUint64(tx.Gas()), tx.GasFeeCap())
	s := &chain.Summary{
		Chain:         c.cfg.ID,
		Nonce:         tx.Nonce(),
		MaxFee:        maxFee.String(),
		MaxFeeDisplay: chain.FormatAmount(maxFee, native.Decimals) + " " + native.Symbol,
		Sighash:       hex.EncodeToString(c.signer().Hash(tx).Bytes()),
	}
	if len(tx.Data()) == 0 {
		if tx.Value().Sign() <= 0 {
			return nil, errors.New("evm: transfer value must be positive")
		}
		s.Asset, s.To, s.Amount = native.Symbol, tx.To().Hex(), tx.Value().String()
		s.AmountDisplay = chain.FormatAmount(tx.Value(), native.Decimals) + " " + native.Symbol
		return s, nil
	}
	if tx.Value().Sign() != 0 {
		return nil, errors.New("evm: token transfer must not carry native value")
	}
	token, ok := c.tokenByContract(*tx.To())
	if !ok {
		return nil, fmt.Errorf("evm: %s is not a configured token contract on %s", tx.To().Hex(), c.cfg.ID)
	}
	to, amount, err := DecodeTransfer(tx.Data())
	if err != nil {
		return nil, err
	}
	if amount.Sign() <= 0 {
		return nil, errors.New("evm: token amount must be positive")
	}
	s.Asset, s.Contract, s.To, s.Amount = token.Symbol, token.Contract, to.Hex(), amount.String()
	s.AmountDisplay = chain.FormatAmount(amount, token.Decimals) + " " + token.Symbol
	return s, nil
}

// ApplySignature implements chain.TxCodec.
func (c *Chain) ApplySignature(raw, sig65 []byte, from string) ([]byte, string, error) {
	tx, err := c.decode(raw)
	if err != nil {
		return nil, "", err
	}
	want, err := ParseAddress(from)
	if err != nil {
		return nil, "", err
	}
	if len(sig65) != 65 || sig65[64] > 1 {
		return nil, "", errors.New("evm: signature must be 65 bytes r||s||v with v in {0,1}")
	}
	signed, err := tx.WithSignature(c.signer(), sig65)
	if err != nil {
		return nil, "", err
	}
	sender, err := types.Sender(c.signer(), signed)
	if err != nil {
		return nil, "", fmt.Errorf("evm: recover sender: %w", err)
	}
	if sender != want {
		return nil, "", fmt.Errorf("evm: signature recovers to %s, not wallet %s", sender.Hex(), want.Hex())
	}
	out, err := signed.MarshalBinary()
	if err != nil {
		return nil, "", err
	}
	return out, signed.Hash().Hex(), nil
}
