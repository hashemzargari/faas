package bridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// NewHTTPHandler exposes the DS3 Bridge control API (docs/04 §10):
//
//	POST   /v1/bridges
//	POST   /v1/bridges/{id}/start
//	GET    /v1/bridges/{id}
//	DELETE /v1/bridges/{id}
//
// This is a control plane, not S3: JSON in/out, no SigV4. Bind it to a private
// interface; it carries source/target credentials in the create body.
func NewHTTPHandler(m *Manager) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/bridges", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var req CreateRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		if err := dec.Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", err))
			return
		}
		st, err := m.Create(r.Context(), req)
		if err != nil {
			writeBridgeError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"bridge_id": st.BridgeID, "status": st.Status})
	})
	mux.HandleFunc("POST /v1/bridges/{id}/start", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := m.Start(id); err != nil {
			writeBridgeError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/bridges/{id}", func(w http.ResponseWriter, r *http.Request) {
		st, err := m.Status(r.PathValue("id"))
		if err != nil {
			writeBridgeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, st)
	})
	mux.HandleFunc("DELETE /v1/bridges/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := m.Delete(r.PathValue("id")); err != nil {
			writeBridgeError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeBridgeError(w http.ResponseWriter, err error) {
	var lockErr *ObjectLockError
	switch {
	case errors.As(err, &lockErr):
		writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, ErrNotFound) || isUnknownBridge(err):
		writeAPIError(w, http.StatusNotFound, err.Error())
	default:
		writeAPIError(w, http.StatusBadRequest, err.Error())
	}
}

func isUnknownBridge(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "bridge: unknown bridge")
}
