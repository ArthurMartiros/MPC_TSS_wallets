package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"thresholdvault/internal/identity"
	"thresholdvault/internal/mpc"
)

type pair struct {
	ta, tb *Transport
}

// newPair wires two transports through a relay. mutate, if set, can rewrite
// or duplicate every inbox response (a malicious relay).
func newPair(t *testing.T, mutate func([]Message) []Message) *pair {
	t.Helper()
	relay := NewServer()
	h := relay.Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mutate == nil || r.Method != http.MethodGet {
			h.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		var resp InboxResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			w.WriteHeader(rec.Code)
			_, _ = w.Write(rec.Body.Bytes())
			return
		}
		orig := len(resp.Messages)
		resp.Messages = mutate(resp.Messages)
		resp.Next += len(resp.Messages) - orig // keep the cursor self-consistent
		writeJSON(w, http.StatusOK, resp)
	}))
	t.Cleanup(srv.Close)

	alice, _ := identity.Generate("alice")
	bob, _ := identity.Generate("bob")
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	ta, err := Dial(TransportConfig{BaseURL: srv.URL, SessionID: "s1", Self: alice, Peers: map[string]*identity.Public{"bob": &bob.Public}, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	tb, err := Dial(TransportConfig{BaseURL: srv.URL, SessionID: "s1", Self: bob, Peers: map[string]*identity.Public{"alice": &alice.Public}, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ta.Close)
	t.Cleanup(tb.Close)
	return &pair{ta: ta, tb: tb}
}

func receive(t *testing.T, tr *Transport, wait time.Duration) (mpc.Envelope, bool) {
	t.Helper()
	select {
	case env := <-tr.Receive():
		return env, true
	case <-time.After(wait):
		return mpc.Envelope{}, false
	}
}

func TestDeliversEncryptedAuthenticatedMessages(t *testing.T) {
	p := newPair(t, nil)
	ctx := context.Background()
	if err := p.ta.Send(ctx, mpc.Envelope{SessionID: "s1", To: []string{"bob"}, Payload: []byte("p2p secret")}); err != nil {
		t.Fatal(err)
	}
	if err := p.ta.Send(ctx, mpc.Envelope{SessionID: "s1", Broadcast: true, Payload: []byte("broadcast")}); err != nil {
		t.Fatal(err)
	}
	env, ok := receive(t, p.tb, 5*time.Second)
	if !ok || string(env.Payload) != "p2p secret" || env.From != "alice" || env.Broadcast {
		t.Fatalf("got %+v ok=%v", env, ok)
	}
	env, ok = receive(t, p.tb, 5*time.Second)
	if !ok || string(env.Payload) != "broadcast" || !env.Broadcast {
		t.Fatalf("got %+v ok=%v", env, ok)
	}
}

func TestRelaySeesOnlyCiphertext(t *testing.T) {
	var seen [][]byte
	relay := NewServer()
	h := relay.Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			seen = append(seen, body)
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()
	alice, _ := identity.Generate("alice")
	bob, _ := identity.Generate("bob")
	ta, _ := Dial(TransportConfig{BaseURL: srv.URL, SessionID: "s1", Self: alice, Peers: map[string]*identity.Public{"bob": &bob.Public}})
	defer ta.Close()
	secret := []byte("SHAMIR-SHARE-0123456789")
	if err := ta.Send(context.Background(), mpc.Envelope{To: []string{"bob"}, Payload: secret}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 {
		t.Fatalf("relay saw %d posts", len(seen))
	}
	if bytes.Contains(seen[0], secret) {
		t.Fatal("relay saw plaintext payload")
	}
}

func TestMaliciousRelayCannotInjectOrReplay(t *testing.T) {
	cases := map[string]func([]Message) []Message{
		"tampered ciphertext": func(ms []Message) []Message {
			for i := range ms {
				ms[i].Box[0] ^= 1
			}
			return ms
		},
		"replayed message": func(ms []Message) []Message {
			// Serve every genuine message twice.
			return append(ms, ms...)
		},
		"forged sender": func(ms []Message) []Message {
			mallory, _ := identity.Generate("alice")
			for i := range ms {
				ms[i].Sig = mallory.Sign(ms[i].signingBytes())
			}
			return ms
		},
		"wrong session": func(ms []Message) []Message {
			for i := range ms {
				ms[i].SessionID = "other"
			}
			return ms
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := newPair(t, mutate)
			if err := p.ta.Send(context.Background(), mpc.Envelope{To: []string{"bob"}, Payload: []byte("hi")}); err != nil {
				t.Fatal(err)
			}
			if name == "replayed message" {
				if _, ok := receive(t, p.tb, 5*time.Second); !ok {
					t.Fatal("genuine message not delivered")
				}
			}
			if env, ok := receive(t, p.tb, 1500*time.Millisecond); ok {
				t.Fatalf("accepted a malicious message: %+v", env)
			}
		})
	}
}

func TestServerRejectsMalformedMessages(t *testing.T) {
	srv := httptest.NewServer(NewServer().Handler())
	defer srv.Close()
	post := func(sid string, m Message) int {
		b, _ := json.Marshal(m)
		resp, err := http.Post(srv.URL+"/relay/v1/sessions/"+sid+"/messages", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	good := Message{SessionID: "s", From: "a", To: "b", Seq: 1, Nonce: make([]byte, 24), Box: []byte{1}, Sig: make([]byte, 64)}
	if code := post("s", good); code != http.StatusAccepted {
		t.Fatalf("good message: %d", code)
	}
	bad := good
	bad.SessionID = "other"
	if code := post("s", bad); code != http.StatusBadRequest {
		t.Errorf("session mismatch: %d", code)
	}
	bad = good
	bad.Nonce = []byte{1}
	if code := post("s", bad); code != http.StatusBadRequest {
		t.Errorf("short nonce: %d", code)
	}
	bad = good
	bad.To = "a"
	if code := post("s", bad); code != http.StatusBadRequest {
		t.Errorf("self-addressed: %d", code)
	}
}
