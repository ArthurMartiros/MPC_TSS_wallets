// Package relay moves MPC protocol messages between signers through an
// untrusted store-and-forward mailbox (hosted by the coordinator).
//
// Every message is encrypted to its single recipient with NaCl box and signed
// by the sender's Ed25519 identity over (session, from, to, seq, broadcast,
// nonce, ciphertext). The relay can drop or delay messages, which makes a
// session time out, but it can't read, forge, redirect or replay them.
package relay

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const signingDomain = "thresholdvault/relay/v1"

// MaxMessageSize bounds one encrypted protocol message. GG18 keygen messages
// carry Paillier/range-proof data and stay well below this.
const MaxMessageSize = 1 << 20

// Message is the relay wire format.
type Message struct {
	SessionID string `json:"session_id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Seq       uint64 `json:"seq"`
	Broadcast bool   `json:"broadcast"`
	Nonce     []byte `json:"nonce"`
	Box       []byte `json:"box"`
	Sig       []byte `json:"sig"`
}

// signingBytes is an unambiguous, length-prefixed encoding of every field
// except Sig.
func (m *Message) signingBytes() []byte {
	var b []byte
	put := func(field []byte) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(field)))
		b = append(b, field...)
	}
	put([]byte(signingDomain))
	put([]byte(m.SessionID))
	put([]byte(m.From))
	put([]byte(m.To))
	b = binary.BigEndian.AppendUint64(b, m.Seq)
	if m.Broadcast {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	put(m.Nonce)
	put(m.Box)
	return b
}

func (m *Message) validateShape() error {
	switch {
	case m.SessionID == "" || m.From == "" || m.To == "":
		return errors.New("relay: message missing session/from/to")
	case m.From == m.To:
		return errors.New("relay: message addressed to sender")
	case len(m.Nonce) != 24:
		return errors.New("relay: bad nonce length")
	case len(m.Box) == 0 || len(m.Box) > MaxMessageSize:
		return fmt.Errorf("relay: bad payload size %d", len(m.Box))
	case len(m.Sig) != 64:
		return errors.New("relay: bad signature length")
	}
	return nil
}
