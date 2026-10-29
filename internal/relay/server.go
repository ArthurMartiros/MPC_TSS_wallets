package relay

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"
)

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// Server is an in-memory mailbox relay. It is deliberately dumb: it doesn't
// verify signatures or know session membership, because signers don't trust
// it anyway. Limits only bound memory use.
type Server struct {
	TTL           time.Duration // sessions older than this are dropped
	MaxWait       time.Duration // long-poll ceiling
	MaxPerMailbox int
	MaxSessions   int
	now           func() time.Time

	mu        sync.Mutex
	sessions  map[string]*session
	lastSweep time.Time
}

type session struct {
	created time.Time
	boxes   map[string][]Message
	notify  chan struct{} // closed and replaced whenever a message arrives
}

func NewServer() *Server {
	return &Server{
		TTL:           15 * time.Minute,
		MaxWait:       25 * time.Second,
		MaxPerMailbox: 1000,
		MaxSessions:   10000,
		now:           time.Now,
		sessions:      map[string]*session{},
	}
}

// Handler returns the relay HTTP API:
//
//	POST /relay/v1/sessions/{sid}/messages        body: Message
//	GET  /relay/v1/sessions/{sid}/inbox/{party}?after=N&wait=SECONDS
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /relay/v1/sessions/{sid}/messages", s.handlePost)
	mux.HandleFunc("GET /relay/v1/sessions/{sid}/inbox/{party}", s.handleInbox)
	return mux
}

// InboxResponse is returned by the inbox endpoint. Next is the cursor to pass
// as `after` on the following poll.
type InboxResponse struct {
	Messages []Message `json:"messages"`
	Next     int       `json:"next"`
}

func (s *Server) handlePost(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if !idRE.MatchString(sid) {
		httpError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	var m Message
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*MaxMessageSize)).Decode(&m); err != nil {
		httpError(w, http.StatusBadRequest, "invalid message: "+err.Error())
		return
	}
	if m.SessionID != sid || !idRE.MatchString(m.To) || !idRE.MatchString(m.From) {
		httpError(w, http.StatusBadRequest, "session/party mismatch")
		return
	}
	if err := m.validateShape(); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.deposit(m); err != nil {
		httpError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) deposit(m Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	sess, ok := s.sessions[m.SessionID]
	if !ok {
		if len(s.sessions) >= s.MaxSessions {
			return errors.New("relay: too many sessions")
		}
		sess = &session{created: s.now(), boxes: map[string][]Message{}, notify: make(chan struct{})}
		s.sessions[m.SessionID] = sess
	}
	if len(sess.boxes[m.To]) >= s.MaxPerMailbox {
		return errors.New("relay: mailbox full")
	}
	sess.boxes[m.To] = append(sess.boxes[m.To], m)
	close(sess.notify)
	sess.notify = make(chan struct{})
	return nil
}

func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request) {
	sid, party := r.PathValue("sid"), r.PathValue("party")
	if !idRE.MatchString(sid) || !idRE.MatchString(party) {
		httpError(w, http.StatusBadRequest, "invalid session or party")
		return
	}
	after, err := strconv.Atoi(r.URL.Query().Get("after"))
	if err != nil || after < 0 {
		after = 0
	}
	wait := 0 * time.Second
	if v, err := strconv.Atoi(r.URL.Query().Get("wait")); err == nil && v > 0 {
		wait = min(time.Duration(v)*time.Second, s.MaxWait)
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()

	for {
		msgs, notify := s.read(sid, party, after)
		if len(msgs) > 0 || wait == 0 {
			writeJSON(w, http.StatusOK, InboxResponse{Messages: msgs, Next: after + len(msgs)})
			return
		}
		select {
		case <-notify:
		case <-deadline.C:
			wait = 0
		case <-r.Context().Done():
			return
		}
	}
}

// read returns messages after cursor and a channel closed on the next deposit.
func (s *Server) read(sid, party string, after int) ([]Message, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sid]
	if !ok {
		// Create the session lazily so a receiver can wait before any sender
		// has posted.
		sess = &session{created: s.now(), boxes: map[string][]Message{}, notify: make(chan struct{})}
		if len(s.sessions) < s.MaxSessions {
			s.sessions[sid] = sess
		}
	}
	box := sess.boxes[party]
	if after >= len(box) {
		return nil, sess.notify
	}
	return append([]Message(nil), box[after:]...), sess.notify
}

func (s *Server) sweepLocked() {
	now := s.now()
	if now.Sub(s.lastSweep) < time.Minute {
		return
	}
	s.lastSweep = now
	for id, sess := range s.sessions {
		if now.Sub(sess.created) > s.TTL {
			delete(s.sessions, id)
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
