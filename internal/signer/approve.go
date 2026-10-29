package signer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"thresholdvault/internal/approval"
	"thresholdvault/internal/chain"
)

// reviewTTL bounds the time between showing a transaction and confirming it.
const reviewTTL = 10 * time.Minute

// ReviewRequest asks the user signer to decode a transaction for review.
type ReviewRequest struct {
	TxID        string `json:"tx_id"`
	WalletID    string `json:"wallet_id"`
	Chain       string `json:"chain"`
	Transaction string `json:"transaction"` // hex unsigned tx, as returned by the coordinator
}

// ReviewResponse is the user signer's own reading of the transaction.
type ReviewResponse struct {
	TxID     string         `json:"tx_id"`
	WalletID string         `json:"wallet_id"`
	From     string         `json:"from"` // derived from this signer's key share
	Summary  *chain.Summary `json:"summary"`
	// ConfirmBefore is when this review expires.
	ConfirmBefore time.Time `json:"confirm_before"`
}

// ConfirmRequest records the user's explicit approval of a reviewed
// transaction. Sighash must echo the reviewed one, so a confirmation can't
// apply to different contents.
type ConfirmRequest struct {
	TxID    string `json:"tx_id"`
	Sighash string `json:"sighash"`
}

// ConfirmResponse carries the approval token for the coordinator.
type ConfirmResponse struct {
	TxID      string    `json:"tx_id"`
	Approval  string    `json:"approval"`
	ExpiresAt time.Time `json:"expires_at"`
}

type pendingReview struct {
	walletID, chain, sighash string
	at                       time.Time
}

// Review decodes the transaction with this signer's own chain adapter and
// remembers it for confirmation. It never trusts the coordinator's summary.
func (s *Signer) Review(_ context.Context, req ReviewRequest) (*ReviewResponse, error) {
	if !walletIDRE.MatchString(req.TxID) {
		return nil, fmt.Errorf("%w: invalid transaction id", ErrBadRequest)
	}
	if s.cfg.Chains == nil {
		return nil, fmt.Errorf("%w: signer has no chain registry", ErrBadRequest)
	}
	share, err := s.LoadShare(req.WalletID)
	if err != nil {
		return nil, err
	}
	c, err := s.cfg.Chains.Get(req.Chain)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	codec, ok := c.(chain.TxCodec)
	if !ok {
		return nil, fmt.Errorf("%w: chain %s has no transaction support", ErrBadRequest, req.Chain)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(req.Transaction, "0x"))
	if err != nil {
		return nil, fmt.Errorf("%w: transaction is not valid hex", ErrBadRequest)
	}
	summary, err := codec.DecodeUnsigned(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	from, err := c.Address(share.PublicKey())
	if err != nil {
		return nil, err
	}

	now := time.Now()
	s.mu.Lock()
	s.reviews[req.TxID] = pendingReview{walletID: req.WalletID, chain: req.Chain, sighash: summary.Sighash, at: now}
	s.mu.Unlock()
	s.log.Info("transaction under review", "tx", req.TxID, "to", summary.To, "amount", summary.AmountDisplay, "max_fee", summary.MaxFeeDisplay)
	return &ReviewResponse{TxID: req.TxID, WalletID: req.WalletID, From: from, Summary: summary, ConfirmBefore: now.Add(reviewTTL)}, nil
}

// Confirm records the user's approval of a reviewed transaction and returns
// a signed approval token.
func (s *Signer) Confirm(_ context.Context, req ConfirmRequest) (*ConfirmResponse, error) {
	s.mu.Lock()
	rev, ok := s.reviews[req.TxID]
	if ok {
		delete(s.reviews, req.TxID)
	}
	s.mu.Unlock()
	now := time.Now()
	switch {
	case !ok:
		return nil, fmt.Errorf("%w: transaction %s has not been reviewed on this signer", ErrBadRequest, req.TxID)
	case now.Sub(rev.at) > reviewTTL:
		return nil, fmt.Errorf("%w: review expired; review again", ErrBadRequest)
	case !strings.EqualFold(rev.sighash, req.Sighash):
		return nil, fmt.Errorf("%w: sighash does not match the reviewed transaction", ErrBadRequest)
	}
	tok, claims, err := approval.Issue(s.id, approval.Claims{
		TxID: req.TxID, WalletID: rev.walletID, Chain: rev.chain, Sighash: rev.sighash,
	}, now, approval.DefaultTTL)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	if err := s.store.Put(approvalRecord(req.TxID), raw); err != nil {
		return nil, err
	}
	s.log.Info("transaction approved by user", "tx", req.TxID, "sighash", rev.sighash)
	return &ConfirmResponse{TxID: req.TxID, Approval: tok, ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC()}, nil
}
