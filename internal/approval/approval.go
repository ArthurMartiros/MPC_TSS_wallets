// Package approval issues and verifies user approval tokens: an Ed25519
// signature by the user signer's identity over exactly which transaction
// (id, wallet, chain, sighash) the user reviewed and confirmed, with expiry.
package approval

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"thresholdvault/internal/identity"
)

const domain = "thresholdvault/approval/v1"

// DefaultTTL is how long an approval stays valid for signing.
const DefaultTTL = time.Hour

// Claims identify the approved transaction.
type Claims struct {
	TxID      string `json:"tx_id"`
	WalletID  string `json:"wallet_id"`
	Chain     string `json:"chain"`
	Sighash   string `json:"sighash"` // lowercase hex
	Signer    string `json:"signer"`  // identity name of the approver
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

type token struct {
	Claims
	Sig []byte `json:"sig"`
}

func (c *Claims) signingBytes() []byte {
	var b []byte
	put := func(s string) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
		b = append(b, s...)
	}
	put(domain)
	put(c.TxID)
	put(c.WalletID)
	put(c.Chain)
	put(strings.ToLower(c.Sighash))
	put(c.Signer)
	b = binary.BigEndian.AppendUint64(b, uint64(c.IssuedAt))
	return binary.BigEndian.AppendUint64(b, uint64(c.ExpiresAt))
}

// Issue signs claims with the approver's identity and returns the token.
func Issue(id *identity.Identity, c Claims, now time.Time, ttl time.Duration) (string, Claims, error) {
	if c.TxID == "" || c.WalletID == "" || c.Chain == "" || c.Sighash == "" {
		return "", Claims{}, errors.New("approval: incomplete claims")
	}
	c.Signer = id.Name
	c.Sighash = strings.ToLower(c.Sighash)
	c.IssuedAt = now.Unix()
	c.ExpiresAt = now.Add(ttl).Unix()
	raw, err := json.Marshal(token{Claims: c, Sig: id.Sign(c.signingBytes())})
	if err != nil {
		return "", Claims{}, err
	}
	return base64.RawURLEncoding.EncodeToString(raw), c, nil
}

// Parse decodes a token without verifying it.
func Parse(tok string) (*Claims, []byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(tok))
	if err != nil {
		return nil, nil, errors.New("approval: malformed token")
	}
	var t token
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, nil, errors.New("approval: malformed token")
	}
	return &t.Claims, t.Sig, nil
}

// Verify checks that tok was issued by approver for exactly want (TxID,
// WalletID, Chain, Sighash) and has not expired.
func Verify(tok string, approver *identity.Public, want Claims, now time.Time) (*Claims, error) {
	c, sig, err := Parse(tok)
	if err != nil {
		return nil, err
	}
	if c.Signer != approver.Name {
		return nil, fmt.Errorf("approval: issued by %q, expected %q", c.Signer, approver.Name)
	}
	if !approver.Verify(c.signingBytes(), sig) {
		return nil, errors.New("approval: bad signature")
	}
	switch {
	case c.TxID != want.TxID:
		return nil, errors.New("approval: issued for a different transaction")
	case c.WalletID != want.WalletID:
		return nil, errors.New("approval: issued for a different wallet")
	case c.Chain != want.Chain:
		return nil, errors.New("approval: issued for a different chain")
	case !strings.EqualFold(c.Sighash, want.Sighash):
		return nil, errors.New("approval: transaction contents changed since approval")
	case now.Unix() >= c.ExpiresAt:
		return nil, errors.New("approval: expired")
	case c.IssuedAt > now.Add(time.Minute).Unix():
		return nil, errors.New("approval: issued in the future")
	}
	return c, nil
}
