package agentbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"lineops-agent/internal/release"
	"net/http"
	"time"
)

type lifecycleReconcileOperations interface {
	LifecycleReconcile(context.Context, release.LifecycleReconcileRequest) (release.LifecycleObservation, error)
}

func (c *Client) LifecycleReconcile(ctx context.Context, r release.LifecycleReconcileRequest) (release.LifecycleObservation, error) {
	var result release.LifecycleObservation
	if !r.Valid() {
		return result, &Error{Code: "invalid_lifecycle_reconcile_request"}
	}
	data, err := json.Marshal(r)
	if err != nil {
		return result, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "http://lineops-executor/v1/singbox/reconcile", bytes.NewReader(data))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return result, &Error{Code: "lifecycle_observation_transport_failure", Unknown: true}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return result, &Error{Code: "lifecycle_observation_rejected", Unknown: true}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8193))
	if err != nil || len(raw) > 8192 || json.Unmarshal(raw, &result) != nil || !result.Matches(r) {
		return release.LifecycleObservation{}, &Error{Code: "lifecycle_invalid_observation", Unknown: true}
	}
	return result, nil
}

func (h *handler) serveLifecycleReconcile(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
		respond(w, 400, release.State{}, "invalid_request")
		return
	}
	var req release.LifecycleReconcileRequest
	if decode(w, r, &req) != nil || !req.Valid() {
		respond(w, 400, release.State{}, "invalid_lifecycle_reconcile_request")
		return
	}
	op, ok := h.engine.(lifecycleReconcileOperations)
	if !ok {
		respond(w, 501, release.State{}, "lifecycle_reconcile_unsupported")
		return
	}
	select {
	case h.active <- struct{}{}:
		defer func() { <-h.active }()
	default:
		respond(w, 429, release.State{}, "executor_busy")
		return
	}
	// Observation does not mutate runtime/configuration and need not continue
	// after lease loss. Its durable authority marker remains effective.
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	result, err := op.LifecycleReconcile(ctx, req)
	if err != nil || !result.Matches(req) {
		respond(w, 409, release.State{}, "lifecycle_observation_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(result)
}
