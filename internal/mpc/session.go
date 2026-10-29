package mpc

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/bnb-chain/tss-lib/v2/tss"
)

// outBuffer bounds how many messages a party may emit during one Start/Update
// call. GG18/20 emits at most one broadcast plus n-1 P2P messages per round.
const outBuffer = 64

// session drives one tss.Party over a Transport. It is single-threaded: after
// each Start/Update it flushes every queued outbound message before reading
// the next inbound one, so nothing is lost when the party finishes.
type session struct {
	id      string
	self    *tss.PartyID
	parties tss.SortedPartyIDs
	tr      Transport
	out     chan tss.Message
}

func newSession(id string, self *tss.PartyID, parties tss.SortedPartyIDs, tr Transport) *session {
	return &session{id: id, self: self, parties: parties, tr: tr, out: make(chan tss.Message, outBuffer)}
}

// run starts party and pumps messages until a value arrives on end.
func run[T any](ctx context.Context, s *session, party tss.Party, end <-chan T) (T, error) {
	var zero T
	if err := callTSS(func() *tss.Error { return party.Start() }); err != nil {
		return zero, fmt.Errorf("mpc: start: %w", err)
	}
	for {
		if err := s.flush(ctx); err != nil {
			return zero, err
		}
		select {
		case result := <-end:
			// Flush once more: a final round may have queued messages for
			// peers that are still waiting.
			if err := s.flush(ctx); err != nil {
				return zero, err
			}
			return result, nil
		default:
		}

		select {
		case <-ctx.Done():
			return zero, fmt.Errorf("mpc: session %s: %w", s.id, ctx.Err())
		case result := <-end:
			if err := s.flush(ctx); err != nil {
				return zero, err
			}
			return result, nil
		case env, ok := <-s.tr.Receive():
			if !ok {
				return zero, errors.New("mpc: transport closed")
			}
			if err := s.deliver(party, env); err != nil {
				return zero, err
			}
		}
	}
}

// deliver validates an inbound envelope and feeds it to the party.
func (s *session) deliver(party tss.Party, env Envelope) error {
	if env.SessionID != s.id {
		return nil // stale or foreign session; ignore
	}
	from := find(s.parties, env.From)
	if from == nil {
		return fmt.Errorf("mpc: message from non-member %q", env.From)
	}
	if from.Id == s.self.Id {
		return nil
	}
	if !env.Broadcast && !slices.Contains(env.To, s.self.Id) {
		return fmt.Errorf("mpc: misrouted p2p message from %q", env.From)
	}
	return callTSS(func() *tss.Error {
		_, err := party.UpdateFromBytes(env.Payload, from, env.Broadcast)
		return err
	})
}

// flush sends every queued outbound message without blocking on the queue.
func (s *session) flush(ctx context.Context) error {
	for {
		select {
		case msg := <-s.out:
			if err := s.send(ctx, msg); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

func (s *session) send(ctx context.Context, msg tss.Message) error {
	payload, routing, err := msg.WireBytes()
	if err != nil {
		return fmt.Errorf("mpc: encode message: %w", err)
	}
	env := Envelope{SessionID: s.id, From: s.self.Id, Broadcast: routing.IsBroadcast, Payload: payload}
	if !routing.IsBroadcast {
		for _, to := range routing.To {
			env.To = append(env.To, to.Id)
		}
	}
	if err := s.tr.Send(ctx, env); err != nil {
		return fmt.Errorf("mpc: send %s: %w", msg.Type(), err)
	}
	return nil
}

// callTSS converts tss-lib errors (including the panics it uses for some
// invalid inputs) into Go errors and preserves culprit information.
func callTSS(fn func() *tss.Error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("mpc: tss-lib panic: %v", r)
		}
	}()
	if tErr := fn(); tErr != nil {
		return &ProtocolError{Err: tErr}
	}
	return nil
}

// ProtocolError is a tss-lib failure. Culprits lists the parties that tss-lib
// identified as misbehaving, if any.
type ProtocolError struct {
	Err *tss.Error
}

func (e *ProtocolError) Error() string { return e.Err.Error() }
func (e *ProtocolError) Unwrap() error { return e.Err.Cause() }

func (e *ProtocolError) Culprits() []string {
	var names []string
	for _, c := range e.Err.Culprits() {
		names = append(names, c.Id)
	}
	return names
}
