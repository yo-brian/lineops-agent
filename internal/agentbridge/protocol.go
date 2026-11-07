// Package agentbridge is the narrow privilege boundary between the unprivileged
// Agent and the root-owned local release executor. It exposes no shell or file API.
package agentbridge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"lineop-agent/internal/release"
	"lineop-agent/internal/traffic"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const DefaultSocket = "/run/lineops-executor/executor.sock"
const MaxRequestBytes = 8 << 20

type PolicyRequest struct {
	InstanceID string            `json:"instance_id"`
	Policies   release.PolicySet `json:"policies"`
}
type StatusRequest struct {
	InstanceID string `json:"instance_id"`
}
type ReceiptRequest struct {
	InstanceID string `json:"instance_id"`
	TaskID     string `json:"task_id"`
}
type Response struct {
	Traffic      []traffic.Sample `json:"traffic,omitempty"`
	Capabilities []string         `json:"capabilities,omitempty"`
	Templates    []string         `json:"templates,omitempty"`
	State        release.State    `json:"state"`
	ErrorCode    string           `json:"error_code,omitempty"`
}
type Error struct {
	Code    string
	Unknown bool
}

func (e *Error) Error() string { return "local executor: " + e.Code }

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

type operations interface {
	Apply(context.Context, release.Request) (release.State, error)
	UpdatePolicies(context.Context, string, release.PolicySet) (release.State, error)
	Status(string) (release.State, error)
}
type verificationOperations interface {
	VerifyStatus(context.Context, string) (release.State, error)
}
type receiptOperations interface {
	Receipt(string, string) (release.State, error)
}
type handler struct {
	engine               operations
	validateRegistration func(string) error
	active               chan struct{}
	verifying            chan struct{}
}

func decode(w http.ResponseWriter, r *http.Request, out any) error {
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBytes)
	defer r.Body.Close()
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return errors.New("invalid bounded JSON")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON rejected")
	}
	return nil
}
func respond(w http.ResponseWriter, status int, s release.State, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Response{State: s, ErrorCode: code})
}
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/singbox/reconcile" {
		h.serveLifecycleReconcile(w, r)
		return
	}
	if r.URL.Path == "/v1/singbox" || r.URL.Path == "/v1/singbox/receipt" {
		h.serveLifecycle(w, r)
		return
	}
	if r.Method != "POST" || r.URL.RawQuery != "" || (r.URL.Path != "/v1/apply" && r.URL.Path != "/v1/policy" && r.URL.Path != "/v1/status" && r.URL.Path != "/v1/ready" && r.URL.Path != "/v1/verify-status" && r.URL.Path != "/v1/receipt" && r.URL.Path != "/v1/traffic") {
		respond(w, 404, release.State{}, "unsupported_operation")
		return
	}
	if r.URL.Path == "/v1/verify-status" {
		select {
		case h.verifying <- struct{}{}:
			defer func() { <-h.verifying }()
		default:
			respond(w, 429, release.State{}, "verification_busy")
			return
		}
	}
	if strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]) != "application/json" {
		respond(w, 415, release.State{}, "json_required")
		return
	}
	if r.URL.Path == "/v1/apply" || r.URL.Path == "/v1/policy" {
		select {
		case h.active <- struct{}{}:
			defer func() { <-h.active }()
		default:
			respond(w, 429, release.State{}, "executor_busy")
			return
		}
	}
	if r.URL.Path == "/v1/ready" {
		var empty struct{}
		if decode(w, r, &empty) != nil {
			respond(w, 400, release.State{}, "invalid_request")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		capabilities := []string{"singbox_lifecycle_v1", "singbox_restart_v1", "node_traffic_v2"}
		if _, ok := h.engine.(lifecycleReconcileOperations); ok {
			capabilities = append(capabilities, "singbox_reconcile_v1")
		}
		_ = json.NewEncoder(w).Encode(Response{Templates: []string{release.Template, release.MultiProtocolTemplate, release.TCPRelayTemplate, release.TeamTemplate, release.TeamSSTemplate}, Capabilities: capabilities})
		return
	}
	var instance string
	var apply release.Request
	var policy PolicyRequest
	var status StatusRequest
	var receipt ReceiptRequest
	switch r.URL.Path {
	case "/v1/apply":
		if decode(w, r, &apply) != nil {
			respond(w, 400, release.State{}, "invalid_request")
			return
		}
		instance = apply.InstanceID
		if len(apply.Certificates) > 256 || len(apply.TargetGroups) > 256 || len(apply.Model.Nodes) > 256 {
			respond(w, 400, release.State{}, "request_limits_exceeded")
			return
		}
	case "/v1/policy":
		if decode(w, r, &policy) != nil {
			respond(w, 400, release.State{}, "invalid_request")
			return
		}
		instance = policy.InstanceID
	case "/v1/status", "/v1/verify-status", "/v1/traffic":
		if decode(w, r, &status) != nil {
			respond(w, 400, release.State{}, "invalid_request")
			return
		}
		instance = status.InstanceID
	case "/v1/receipt":
		if decode(w, r, &receipt) != nil || !identifier.MatchString(receipt.TaskID) {
			respond(w, 400, release.State{}, "invalid_request")
			return
		}
		instance = receipt.InstanceID
	}
	if !identifier.MatchString(instance) || h.validateRegistration(instance) != nil {
		respond(w, 409, release.State{}, "instance_not_registered")
		return
	}
	if r.URL.Path == "/v1/traffic" {
		reader, ok := h.engine.(interface {
			Traffic(context.Context, string) ([]traffic.Sample, error)
		})
		if !ok {
			respond(w, 501, release.State{}, "traffic_unsupported")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		samples, err := reader.Traffic(ctx, instance)
		if err != nil {
			respond(w, 409, release.State{}, release.TrafficErrorCode(err))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(Response{Traffic: samples})
		return
	}
	if r.URL.Path == "/v1/apply" {
		if e := policyBounds(apply.Policies); e != nil {
			respond(w, 400, release.State{}, "policy_limits_exceeded")
			return
		}
	}
	if r.URL.Path == "/v1/policy" {
		if e := policyBounds(policy.Policies); e != nil {
			respond(w, 400, release.State{}, "policy_limits_exceeded")
			return
		}
	}
	// Once accepted, a lost socket response must not abort a durable release. The
	// engine arms the independent recovery service before changing any pointer.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 6*time.Minute)
	defer cancel()
	var result release.State
	var e error
	switch r.URL.Path {
	case "/v1/apply":
		result, e = h.engine.Apply(ctx, apply)
	case "/v1/policy":
		result, e = h.engine.UpdatePolicies(ctx, instance, policy.Policies)
	case "/v1/status":
		result, e = h.engine.Status(instance)
	case "/v1/verify-status":
		verifier, ok := h.engine.(verificationOperations)
		if !ok {
			respond(w, 501, release.State{}, "verification_unsupported")
			return
		}
		verifyCtx, verifyCancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer verifyCancel()
		result, e = verifier.VerifyStatus(verifyCtx, instance)
		if e != nil && result.LastResult == "succeeded" {
			result.LastResult = "unknown"
			result.ErrorCode = "current_health_unverified"
		}
	case "/v1/receipt":
		reader, ok := h.engine.(receiptOperations)
		if !ok {
			respond(w, 501, release.State{}, "receipt_unsupported")
			return
		}
		result, e = reader.Receipt(instance, receipt.TaskID)
		if e == nil && result.LastTaskID != receipt.TaskID {
			respond(w, 409, release.State{}, "receipt_identity_mismatch")
			return
		}
	}
	if e != nil {
		respond(w, 409, result, errorCode(e))
		return
	}
	respond(w, 200, result, "")
}
func policyBounds(p release.PolicySet) error {
	if len(p.Groups) > 256 {
		return errors.New("too many groups")
	}
	for _, g := range p.Groups {
		if len(g.DisabledReasons) > 8 || len(g.RevokedCredentialIDs) > 4096 {
			return errors.New("policy too large")
		}
		for _, id := range g.RevokedCredentialIDs {
			if !identifier.MatchString(id) {
				return errors.New("invalid revoked credential")
			}
		}
	}
	return nil
}
func errorCode(e error) string {
	switch e.Error() {
	case "stale generation or fencing", "conflicting task replay":
		return "stale_or_conflicting_task"
	case "invalid task or deployment epoch", "deployment epoch requires manual reconciliation":
		return "epoch_reconciliation_required"
	case "unconfirmed publication requires recovery":
		return "recovery_pending"
	case "baseline health failed":
		return "baseline_unhealthy"
	case "sing_box_check_failed":
		return "configuration_check_failed"
	case "isolated_trial_failed":
		return "isolated_trial_failed"
	case "independent recovery guard unavailable":
		return "recovery_guard_unavailable"
	case "publication failed; previous service safely restored":
		return "failed_rolled_back"
	case "configuration or dependency drift", "current pointer drift":
		return "configuration_drift"
	case "unapproved cross-group semantic change", "unapproved shared TLS dependency change":
		return "unapproved_shared_change"
	case "stale or conflicting policy":
		return "stale_or_conflicting_policy"
	case "fresh_protocol_health_failed":
		return "current_health_failed"
	case "current_version_not_verified", "authorization_policy_unavailable", "authorization_not_verified":
		return e.Error()
	case "configuration_or_dependency_drift", "current_pointer_drift":
		return "configuration_drift"
	case "task receipt unavailable; publication remains unknown":
		return "receipt_unavailable"
	case "receipt identity mismatch":
		return "receipt_identity_mismatch"
	default:
		return "operation_failed"
	}
}
