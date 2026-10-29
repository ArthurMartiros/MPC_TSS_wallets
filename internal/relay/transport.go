package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"thresholdvault/internal/identity"
	"thresholdvault/internal/mpc"
)

// TransportConfig configures one party's end of one session.
type TransportConfig struct {
	BaseURL   string // relay root, e.g. http://vaultd:8080
	SessionID string
	Self      *identity.Identity
	// Peers are the pinned public identities of every other session member,
	// keyed by party name. Messages from anyone else are rejected.
	Peers      map[string]*identity.Public
	HTTPClient *http.Client
	Logger     *slog.Logger
}

// Transport implements mpc.Transport over a relay Server.
type Transport struct {
	cfg  TransportConfig
	in   chan mpc.Envelope
	stop context.CancelFunc
	done chan struct{}

	sendMu sync.Mutex
	seq    uint64
}

var _ mpc.Transport = (*Transport)(nil)

// Dial starts polling the relay for this party's inbox. Call Close when the
// session ends.
func Dial(cfg TransportConfig) (*Transport, error) {
	if cfg.BaseURL == "" || cfg.SessionID == "" || cfg.Self == nil {
		return nil, errors.New("relay: incomplete transport config")
	}
	if !idRE.MatchString(cfg.SessionID) {
		return nil, fmt.Errorf("relay: invalid session id %q", cfg.SessionID)
	}
	for name, p := range cfg.Peers {
		if p == nil || p.Name != name {
			return nil, fmt.Errorf("relay: peer identity for %q is missing or misnamed", name)
		}
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 40 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	t := &Transport{cfg: cfg, in: make(chan mpc.Envelope, 256), stop: cancel, done: make(chan struct{})}
	go t.poll(ctx)
	return t, nil
}

// Close stops the poller.
func (t *Transport) Close() {
	t.stop()
	<-t.done
}

func (t *Transport) Receive() <-chan mpc.Envelope { return t.in }

// Send encrypts env.Payload separately to each recipient and posts it.
func (t *Transport) Send(ctx context.Context, env mpc.Envelope) error {
	recipients := env.To
	if env.Broadcast {
		recipients = recipients[:0:0]
		for name := range t.cfg.Peers {
			recipients = append(recipients, name)
		}
	}
	for _, to := range recipients {
		peer, ok := t.cfg.Peers[to]
		if !ok {
			return fmt.Errorf("relay: no pinned identity for recipient %q", to)
		}
		nonce, box, err := t.cfg.Self.Seal(peer, env.Payload)
		if err != nil {
			return err
		}
		t.sendMu.Lock()
		t.seq++
		m := Message{
			SessionID: t.cfg.SessionID,
			From:      t.cfg.Self.Name,
			To:        to,
			Seq:       t.seq,
			Broadcast: env.Broadcast,
			Nonce:     nonce[:],
			Box:       box,
		}
		m.Sig = t.cfg.Self.Sign(m.signingBytes())
		t.sendMu.Unlock()
		if err := t.post(ctx, m); err != nil {
			return err
		}
	}
	return nil
}

func (t *Transport) post(ctx context.Context, m Message) error {
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	u := t.cfg.BaseURL + "/relay/v1/sessions/" + url.PathEscape(m.SessionID) + "/messages"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("relay: post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("relay: post rejected (%d): %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}

func (t *Transport) poll(ctx context.Context) {
	defer close(t.done)
	cursor := 0
	lastSeq := map[string]uint64{}
	for ctx.Err() == nil {
		resp, err := t.fetch(ctx, cursor)
		if err != nil {
			if ctx.Err() == nil {
				t.cfg.Logger.Debug("relay poll failed", "err", err)
				select {
				case <-time.After(300 * time.Millisecond):
				case <-ctx.Done():
				}
			}
			continue
		}
		cursor = resp.Next
		for _, m := range resp.Messages {
			env, err := t.open(m, lastSeq)
			if err != nil {
				// A relay or network attacker can only cause drops: the
				// session then times out instead of accepting bad input.
				t.cfg.Logger.Warn("relay: dropped message", "from", m.From, "session", m.SessionID, "err", err)
				continue
			}
			select {
			case t.in <- env:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (t *Transport) fetch(ctx context.Context, cursor int) (*InboxResponse, error) {
	u := fmt.Sprintf("%s/relay/v1/sessions/%s/inbox/%s?after=%s&wait=20",
		t.cfg.BaseURL, url.PathEscape(t.cfg.SessionID), url.PathEscape(t.cfg.Self.Name), strconv.Itoa(cursor))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := t.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("relay: inbox status %d", resp.StatusCode)
	}
	var out InboxResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*MaxMessageSize)).Decode(&out); err != nil {
		return nil, err
	}
	if out.Next < cursor || out.Next != cursor+len(out.Messages) {
		return nil, errors.New("relay: inconsistent inbox cursor")
	}
	return &out, nil
}

// open authenticates, de-duplicates and decrypts one inbound message.
func (t *Transport) open(m Message, lastSeq map[string]uint64) (mpc.Envelope, error) {
	if err := m.validateShape(); err != nil {
		return mpc.Envelope{}, err
	}
	if m.SessionID != t.cfg.SessionID || m.To != t.cfg.Self.Name {
		return mpc.Envelope{}, errors.New("message not addressed to this session/party")
	}
	peer, ok := t.cfg.Peers[m.From]
	if !ok {
		return mpc.Envelope{}, errors.New("sender is not a pinned session member")
	}
	if !peer.Verify(m.signingBytes(), m.Sig) {
		return mpc.Envelope{}, errors.New("bad sender signature")
	}
	if m.Seq <= lastSeq[m.From] {
		return mpc.Envelope{}, fmt.Errorf("replayed or reordered message (seq %d <= %d)", m.Seq, lastSeq[m.From])
	}
	var nonce [24]byte
	copy(nonce[:], m.Nonce)
	payload, err := t.cfg.Self.Open(peer, nonce, m.Box)
	if err != nil {
		return mpc.Envelope{}, err
	}
	lastSeq[m.From] = m.Seq
	env := mpc.Envelope{SessionID: m.SessionID, From: m.From, Broadcast: m.Broadcast, Payload: payload}
	if !m.Broadcast {
		env.To = []string{m.To}
	}
	return env, nil
}
