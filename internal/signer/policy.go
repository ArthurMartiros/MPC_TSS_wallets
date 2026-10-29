package signer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"thresholdvault/internal/approval"
	"thresholdvault/internal/chain"
	"thresholdvault/internal/sharestore"
)

// verifyTx independently decodes the unsigned transaction carried in req
// and checks that the digest the coordinator asks us to sign is really its
// sighash. Signers never sign a bare digest under these policies.
func verifyTx(chains *chain.Registry, req *SignRequest) (*chain.Summary, error) {
	if chains == nil {
		return nil, errors.New("no chain registry configured")
	}
	if req.TxID == "" || req.Chain == "" || req.Transaction == "" {
		return nil, errors.New("request carries no transaction to verify")
	}
	c, err := chains.Get(req.Chain)
	if err != nil {
		return nil, err
	}
	codec, ok := c.(chain.TxCodec)
	if !ok {
		return nil, fmt.Errorf("chain %s has no transaction support", req.Chain)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(req.Transaction, "0x"))
	if err != nil {
		return nil, errors.New("transaction is not valid hex")
	}
	s, err := codec.DecodeUnsigned(raw)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(s.Sighash, req.Digest) {
		return nil, errors.New("digest does not match the transaction's sighash")
	}
	return s, nil
}

func approvalRecord(txID string) string { return "approval/" + txID }

func loadApproval(store *sharestore.Store, txID string) (*approval.Claims, error) {
	if !walletIDRE.MatchString(txID) {
		return nil, errors.New("invalid transaction id")
	}
	raw, err := store.Get(approvalRecord(txID))
	if errors.Is(err, sharestore.ErrNotFound) {
		return nil, fmt.Errorf("transaction %s has not been approved on this device", txID)
	}
	if err != nil {
		return nil, err
	}
	var c approval.Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// UserPolicy is the user signer's policy: sign only transactions the user
// reviewed and confirmed on this signer (see Signer.Review / Confirm), and
// only if the bytes being signed are exactly those that were approved.
type UserPolicy struct {
	Store  *sharestore.Store
	Chains *chain.Registry
	Now    func() time.Time
}

func (p *UserPolicy) Authorize(_ context.Context, req *SignRequest) error {
	s, err := verifyTx(p.Chains, req)
	if err != nil {
		return err
	}
	rec, err := loadApproval(p.Store, req.TxID)
	if err != nil {
		return err
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	switch {
	case rec.WalletID != req.WalletID || rec.Chain != req.Chain:
		return errors.New("approval was for a different wallet or chain")
	case !strings.EqualFold(rec.Sighash, s.Sighash):
		return errors.New("transaction contents changed since the user approved it")
	case now().Unix() >= rec.ExpiresAt:
		return errors.New("approval expired; review and confirm again")
	}
	return nil
}

// CosignerPolicy is the server and backup signers' policy: sign only when
// the request carries a valid approval token from the pinned user identity
// for exactly this transaction.
type CosignerPolicy struct {
	Peers    PeerResolver
	Chains   *chain.Registry
	Approver string // committee role whose approval is required (default "user")
	Now      func() time.Time
}

func (p *CosignerPolicy) Authorize(_ context.Context, req *SignRequest) error {
	s, err := verifyTx(p.Chains, req)
	if err != nil {
		return err
	}
	if req.Approval == "" {
		return errors.New("missing user approval")
	}
	name := p.Approver
	if name == "" {
		name = "user"
	}
	pub, err := p.Peers.Resolve(name)
	if err != nil {
		return err
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	_, err = approval.Verify(req.Approval, pub, approval.Claims{
		TxID: req.TxID, WalletID: req.WalletID, Chain: req.Chain, Sighash: s.Sighash,
	}, now())
	return err
}
