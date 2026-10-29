package signer

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"thresholdvault/internal/mpc"
)

// IdentityResponse is returned by GET /v1/identity.
type IdentityResponse struct {
	Name        string `json:"name"`
	Identity    string `json:"identity"`
	Fingerprint string `json:"fingerprint"`
}

// HealthResponse is returned by GET /v1/health.
type HealthResponse struct {
	Name           string `json:"name"`
	PreParamsReady int    `json:"preparams_ready"`
	Wallets        int    `json:"wallets"`
}

// Handler exposes the signer's API to the coordinator. If token is non-empty,
// every request must carry "Authorization: Bearer <token>". The token only
// gates who may *ask*; whether to sign is always decided by the Authorizer.
func (s *Signer) Handler(token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/identity", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, IdentityResponse{Name: s.cfg.Name, Identity: s.id.Public.String(), Fingerprint: s.id.Fingerprint()})
	})
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		wallets, _ := s.Wallets()
		writeJSON(w, http.StatusOK, HealthResponse{Name: s.cfg.Name, PreParamsReady: s.PreParamsReady(), Wallets: len(wallets)})
	})
	mux.HandleFunc("POST /v1/keygen", func(w http.ResponseWriter, r *http.Request) {
		var req KeygenRequest
		if !decode(w, r, &req) {
			return
		}
		res, err := s.Keygen(r.Context(), req)
		respond(w, res, err)
	})
	mux.HandleFunc("POST /v1/sign", func(w http.ResponseWriter, r *http.Request) {
		var req SignRequest
		if !decode(w, r, &req) {
			return
		}
		res, err := s.Sign(r.Context(), req)
		respond(w, res, err)
	})
	return requireToken(token, mux)
}

// ApprovalHandler exposes the user-only review/confirm API. It must be
// served on a separate listener with a token the coordinator never sees;
// otherwise the coordinator could approve transactions on the user's behalf.
func (s *Signer) ApprovalHandler(token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/approvals/review", func(w http.ResponseWriter, r *http.Request) {
		var req ReviewRequest
		if !decode(w, r, &req) {
			return
		}
		res, err := s.Review(r.Context(), req)
		respond(w, res, err)
	})
	mux.HandleFunc("POST /v1/approvals/confirm", func(w http.ResponseWriter, r *http.Request) {
		var req ConfirmRequest
		if !decode(w, r, &req) {
			return
		}
		res, err := s.Confirm(r.Context(), req)
		respond(w, res, err)
	})
	return requireToken(token, mux)
}

func requireToken(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return false
	}
	return true
}

func respond(w http.ResponseWriter, v any, err error) {
	if err == nil {
		writeJSON(w, http.StatusOK, v)
		return
	}
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrBadRequest), errors.Is(err, mpc.ErrUnknownParty),
		errors.Is(err, mpc.ErrInsufficientQuorum), errors.Is(err, mpc.ErrNotInSession):
		status = http.StatusBadRequest
	case errors.Is(err, ErrNotAuthorized):
		status = http.StatusForbidden
	case errors.Is(err, ErrWalletUnknown):
		status = http.StatusNotFound
	case errors.Is(err, ErrWalletExists), errors.Is(err, ErrSessionReused):
		status = http.StatusConflict
	}
	writeError(w, status, err.Error())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
