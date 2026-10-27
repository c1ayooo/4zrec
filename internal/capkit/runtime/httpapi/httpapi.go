// Package httpapi is the optional generic HTTP surface for a capkit runtime.
// Hosts can mount it directly or implement their own routes using the same
// contracts.
package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/runtime"
)

type Handler struct {
	rt *runtime.Runtime
}

func New(rt *runtime.Runtime) *Handler { return &Handler{rt: rt} }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/tools":
		writeJSON(w, http.StatusOK, map[string]any{"tools": h.rt.Tools()})
	case r.Method == http.MethodGet && r.URL.Path == "/manifests":
		writeJSON(w, http.StatusOK, map[string]any{"manifests": h.rt.Manifests()})
	case r.Method == http.MethodPost && r.URL.Path == "/call":
		var req struct {
			Tool    string           `json:"tool"`
			Input   json.RawMessage  `json:"input"`
			Context core.CallContext `json:"context"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		res, err := h.rt.Call(r.Context(), req.Tool, req.Input, req.Context)
		body := map[string]any{"result": res}
		if err != nil {
			body["error"] = err.Error()
		}
		writeJSON(w, http.StatusOK, body)
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
