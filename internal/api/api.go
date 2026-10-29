// Package api is the coordinator's REST API.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"thresholdvault/internal/coordinator"
	"thresholdvault/internal/relay"
	"thresholdvault/internal/signer"
	"thresholdvault/internal/store"
)

// Server serves the REST API and mounts the MPC relay.
type Server struct {
	Coord *coordinator.Coordinator
	Relay *relay.Server
	// Token, if set, is required as a bearer token on every API route except
	// /healthz and the relay (whose messages are end-to-end authenticated).
	Token  string
	Logger *slog.Logger
}

func (s *Server) Handler() http.Handler {
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	api := http.NewServeMux()
	api.HandleFunc("GET /chains", s.listChains)
	api.HandleFunc("GET /signers", s.signers)
	api.HandleFunc("POST /wallets", s.createWallet)
	api.HandleFunc("GET /wallets", s.listWallets)
	api.HandleFunc("GET /wallets/{id}", s.getWallet)
	api.HandleFunc("GET /wallets/{id}/balance", s.balance)
	api.HandleFunc("POST /transactions/prepare", s.prepareTx)
	api.HandleFunc("GET /transactions", s.listTxs)
	api.HandleFunc("GET /transactions/{id}", s.getTx)
	api.HandleFunc("POST /transactions/{id}/approve", s.approveTx)
	api.HandleFunc("POST /transactions/{id}/sign", s.signTx)
	api.HandleFunc("POST /transactions/{id}/broadcast", s.broadcastTx)

	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	root.Handle("/relay/", s.Relay.Handler())
	root.Handle("/", s.auth(api))
	return s.logRequests(root)
}

func (s *Server) auth(next http.Handler) http.Handler {
	if s.Token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
			writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/relay/") {
			next.ServeHTTP(w, r) // long-polls; too noisy to log
			return
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.Logger.Info("http", "method", r.Method, "path", r.URL.Path, "status", rec.status, "took", time.Since(start).Round(time.Millisecond))
	})
}

type chainInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Family string `json:"family"`
	Assets any    `json:"assets"`
}

func (s *Server) listChains(w http.ResponseWriter, r *http.Request) {
	var out []chainInfo
	for _, c := range s.Coord.Chains().All() {
		out = append(out, chainInfo{ID: c.ID(), Name: c.Name(), Family: string(c.Family()), Assets: c.Assets()})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) signers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Coord.SignerStatuses(r.Context()))
}

// CreateWalletRequest is the body of POST /wallets.
type CreateWalletRequest struct {
	Name string `json:"name"`
}

func (s *Server) createWallet(w http.ResponseWriter, r *http.Request) {
	var req CreateWalletRequest
	if !decode(w, r, &req) {
		return
	}
	// DKG must not be aborted just because an HTTP client disconnected.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Minute)
	defer cancel()
	wallet, err := s.Coord.CreateWallet(ctx, req.Name)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, wallet)
}

func (s *Server) listWallets(w http.ResponseWriter, r *http.Request) {
	ws, err := s.Coord.Wallets(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ws)
}

func (s *Server) getWallet(w http.ResponseWriter, r *http.Request) {
	wallet, err := s.Coord.Wallet(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wallet)
}

func (s *Server) balance(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("chain") == "" {
		writeError(w, http.StatusBadRequest, "query parameter 'chain' is required, e.g. ?chain=ethereum-sepolia")
		return
	}
	res, err := s.Coord.Balance(r.Context(), r.PathValue("id"), q.Get("chain"), q.Get("asset"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) prepareTx(w http.ResponseWriter, r *http.Request) {
	var req coordinator.PrepareRequest
	if !decode(w, r, &req) {
		return
	}
	tx, err := s.Coord.PrepareTransaction(r.Context(), req)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, tx)
}

func (s *Server) listTxs(w http.ResponseWriter, r *http.Request) {
	txs, err := s.Coord.Transactions(r.Context(), r.URL.Query().Get("wallet_id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, txs)
}

func (s *Server) getTx(w http.ResponseWriter, r *http.Request) {
	tx, err := s.Coord.Transaction(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tx)
}

// ApproveRequest is the body of POST /transactions/{id}/approve.
type ApproveRequest struct {
	// Approval is the token returned by the user signer's
	// /v1/approvals/confirm after the user reviewed the transaction.
	Approval string `json:"approval"`
}

func (s *Server) approveTx(w http.ResponseWriter, r *http.Request) {
	var req ApproveRequest
	if !decode(w, r, &req) {
		return
	}
	tx, err := s.Coord.ApproveTransaction(r.Context(), r.PathValue("id"), req.Approval)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tx)
}

func (s *Server) signTx(w http.ResponseWriter, r *http.Request) {
	// Like keygen, signing is not aborted when the HTTP client goes away.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Minute)
	defer cancel()
	tx, err := s.Coord.SignTransaction(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tx)
}

func (s *Server) broadcastTx(w http.ResponseWriter, r *http.Request) {
	tx, err := s.Coord.BroadcastTransaction(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tx)
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	var apiErr *signer.APIError
	switch {
	case errors.Is(err, coordinator.ErrInvalid):
		status = http.StatusBadRequest
	case errors.Is(err, store.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, coordinator.ErrState), errors.Is(err, store.ErrConflict):
		status = http.StatusConflict
	case errors.Is(err, coordinator.ErrUnsupported):
		status = http.StatusNotImplemented
	case errors.Is(err, coordinator.ErrUpstream), errors.As(err, &apiErr):
		status = http.StatusBadGateway
	}
	if status >= 500 {
		s.Logger.Error("request failed", "err", err)
	}
	writeError(w, status, err.Error())
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
