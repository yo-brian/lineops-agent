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

type lifecycleOperations interface {
	Lifecycle(context.Context, release.LifecycleRequest) (release.LifecycleResult, error)
	LifecycleReceipt(release.LifecycleRequest) (release.LifecycleResult, error)
}

func (c *Client) Lifecycle(ctx context.Context, r release.LifecycleRequest, receiptOnly bool) (release.LifecycleResult, error) {
	var result release.LifecycleResult
	path := "/v1/singbox"
	if receiptOnly {
		path += "/receipt"
	}
	data, err := json.Marshal(r)
	if err != nil {
		return result, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "http://lineops-executor"+path, bytes.NewReader(data))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return result, &Error{Code: "lifecycle_transport_failure", Unknown: true}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return result, &Error{Code: "lifecycle_executor_rejected", Unknown: true}
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&result) != nil || !result.Valid() {
		return result, &Error{Code: "lifecycle_invalid_receipt", Unknown: true}
	}
	return result, nil
}
func (h *handler) serveLifecycle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
		respond(w, 400, release.State{}, "invalid_request")
		return
	}
	var req release.LifecycleRequest
	if decode(w, r, &req) != nil || !req.Valid() {
		respond(w, 400, release.State{}, "invalid_lifecycle_request")
		return
	}
	op, ok := h.engine.(lifecycleOperations)
	if !ok {
		respond(w, 501, release.State{}, "lifecycle_unsupported")
		return
	}
	select {
	case h.active <- struct{}{}:
		defer func() { <-h.active }()
	default:
		respond(w, 429, release.State{}, "executor_busy")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Minute)
	defer cancel()
	var result release.LifecycleResult
	var err error
	if r.URL.Path == "/v1/singbox/receipt" {
		result, err = op.LifecycleReceipt(req)
	} else {
		result, err = op.Lifecycle(ctx, req)
	}
	if err != nil {
		respond(w, 409, release.State{}, "lifecycle_receipt_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(result)
}
func (c *Client) Capabilities(ctx context.Context) ([]string, []string, error) {
	var templates, capabilities []string
	_, err := c.call(ctx, "/v1/ready", struct{}{}, &templates, &capabilities)
	return templates, capabilities, err
}
