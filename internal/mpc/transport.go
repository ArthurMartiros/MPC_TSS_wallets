package mpc

import (
	"context"
	"fmt"
	"sync"
)

// Envelope is a single tss-lib protocol message in transit.
type Envelope struct {
	SessionID string   `json:"session_id"`
	From      string   `json:"from"`
	To        []string `json:"to,omitempty"` // empty when Broadcast is true
	Broadcast bool     `json:"broadcast"`
	Payload   []byte   `json:"payload"` // tss-lib wire bytes
}

// Transport delivers envelopes between the parties of one session.
//
// Implementations MUST authenticate the From field (tss-lib trusts it) and
// MUST keep point-to-point payloads confidential from everyone except the
// recipient: keygen round 2 sends Shamir shares point to point.
type Transport interface {
	Send(ctx context.Context, env Envelope) error
	Receive() <-chan Envelope
}

// MemoryHub is an in-process Transport for tests and local demos. It is
// trivially authenticated because each party gets its own endpoint object.
type MemoryHub struct {
	mu      sync.Mutex
	inboxes map[string]chan Envelope
}

func NewMemoryHub(parties []string) *MemoryHub {
	h := &MemoryHub{inboxes: make(map[string]chan Envelope, len(parties))}
	for _, p := range parties {
		h.inboxes[p] = make(chan Envelope, 256)
	}
	return h
}

// Endpoint returns the Transport bound to party name.
func (h *MemoryHub) Endpoint(name string) Transport {
	return &memoryEndpoint{hub: h, self: name}
}

type memoryEndpoint struct {
	hub  *MemoryHub
	self string
}

func (e *memoryEndpoint) Send(ctx context.Context, env Envelope) error {
	env.From = e.self // the hub, not the caller, asserts the sender
	targets := env.To
	e.hub.mu.Lock()
	if env.Broadcast {
		targets = targets[:0:0]
		for name := range e.hub.inboxes {
			if name != e.self {
				targets = append(targets, name)
			}
		}
	}
	inboxes := make([]chan Envelope, 0, len(targets))
	for _, t := range targets {
		ch, ok := e.hub.inboxes[t]
		if !ok {
			e.hub.mu.Unlock()
			return fmt.Errorf("memory hub: unknown recipient %q", t)
		}
		inboxes = append(inboxes, ch)
	}
	e.hub.mu.Unlock()

	for _, ch := range inboxes {
		env := env
		env.Payload = append([]byte(nil), env.Payload...)
		select {
		case ch <- env:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (e *memoryEndpoint) Receive() <-chan Envelope {
	return e.hub.inboxes[e.self]
}
