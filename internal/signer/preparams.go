package signer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"

	"thresholdvault/internal/mpc"
)

const preParamsPrefix = "preparams/"

// AddPreParams stores one set of pre-parameters in the encrypted pool.
func (s *Signer) AddPreParams(p *keygen.LocalPreParams) error {
	if p == nil || !p.ValidateWithProof() {
		return fmt.Errorf("signer: invalid pre-parameters")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	return s.store.Put(preParamsPrefix+hex.EncodeToString(id), raw)
}

// PreParamsReady reports how many pre-parameter sets are pooled.
func (s *Signer) PreParamsReady() int {
	names, err := s.store.List(preParamsPrefix)
	if err != nil {
		return 0
	}
	return len(names)
}

// takePreParams removes one set from the pool so it's never reused. If the
// pool is empty it generates a set inline (slow).
func (s *Signer) takePreParams(ctx context.Context) (*keygen.LocalPreParams, error) {
	s.poolMu.Lock()
	defer s.poolMu.Unlock()
	defer s.kickPool()

	names, err := s.store.List(preParamsPrefix)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		s.log.Warn("pre-parameter pool empty; generating inline (this can take minutes)")
		return mpc.GeneratePreParams(ctx)
	}
	raw, err := s.store.Get(names[0])
	if err != nil {
		return nil, err
	}
	if err := s.store.Delete(names[0]); err != nil {
		return nil, err
	}
	var p keygen.LocalPreParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("signer: decode pre-parameters: %w", err)
	}
	return &p, nil
}

func (s *Signer) kickPool() {
	select {
	case s.poolKick <- struct{}{}:
	default:
	}
}

// RunPreParamsPool keeps `target` pre-parameter sets ready until ctx ends.
func (s *Signer) RunPreParamsPool(ctx context.Context, target int) {
	for ctx.Err() == nil {
		if s.PreParamsReady() < target {
			start := time.Now()
			p, err := mpc.GeneratePreParams(ctx)
			if err != nil {
				if ctx.Err() == nil {
					s.log.Error("pre-parameter generation failed", "err", err)
					time.Sleep(5 * time.Second)
				}
				continue
			}
			if err := s.AddPreParams(p); err != nil {
				s.log.Error("store pre-parameters", "err", err)
				continue
			}
			s.log.Info("pre-parameters ready", "took", time.Since(start).Round(time.Second), "pooled", s.PreParamsReady())
			continue
		}
		select {
		case <-s.poolKick:
		case <-ctx.Done():
		}
	}
}
