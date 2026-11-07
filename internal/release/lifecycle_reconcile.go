package release

import (
	"context"
	"errors"
	"os"
	"regexp"
	"time"
)

var lifecycleObservationError = regexp.MustCompile(`^[a-z][a-z0-9_]{0,99}$`)

// A fresh read-only command has its own authority, distinct from the original
// operation. It must never replay installation, restart or removal.
type LifecycleReconcileRequest struct {
	TaskID     string           `json:"task_id"`
	InstanceID string           `json:"instance_id"`
	Epoch      string           `json:"epoch"`
	Fencing    uint64           `json:"fencing"`
	Original   LifecycleRequest `json:"original"`
}

func (r LifecycleReconcileRequest) Valid() bool {
	return lifecycleID.MatchString(r.TaskID) && r.Fencing > 0 && r.Fencing < 1<<63 && r.Original.Valid() && r.TaskID != r.Original.TaskID && r.InstanceID == r.Original.InstanceID && r.Epoch == r.Original.Epoch && r.Fencing > r.Original.Fencing
}

// Observation reports fresh local evidence separately from a historical receipt.
// Missing/unknown receipts cannot prove that the original restart took place.
type LifecycleObservation struct {
	TaskID         string           `json:"task_id"`
	InstanceID     string           `json:"instance_id"`
	Epoch          string           `json:"epoch"`
	Fencing        uint64           `json:"fencing"`
	OriginalTaskID string           `json:"original_task_id"`
	Receipt        *LifecycleResult `json:"receipt,omitempty"`
	Installed      bool             `json:"installed"`
	Version        string           `json:"version"`
	ServiceState   string           `json:"service_state"`
	ErrorCode      string           `json:"error_code,omitempty"`
	ObservedAt     time.Time        `json:"observed_at"`
}

func (r LifecycleObservation) Valid() bool {
	return lifecycleID.MatchString(r.TaskID) && lifecycleID.MatchString(r.InstanceID) && lifecycleID.MatchString(r.Epoch) && lifecycleID.MatchString(r.OriginalTaskID) && r.TaskID != r.OriginalTaskID && r.Fencing > 0 && r.Fencing < 1<<63 && len(r.ErrorCode) <= 100 && len(r.Version) <= 80 && !r.ObservedAt.IsZero() &&
		(r.ServiceState == "unknown" || (r.ErrorCode == "" && ((r.Installed && r.Version != "" && (r.ServiceState == "running" || r.ServiceState == "stopped")) || (!r.Installed && r.Version == "" && r.ServiceState == "not_installed")))) &&
		(r.Receipt == nil || (r.Receipt.Valid() && r.Receipt.TaskID == r.OriginalTaskID && r.Receipt.InstanceID == r.InstanceID && r.Receipt.Epoch == r.Epoch && r.Receipt.Fencing < r.Fencing))
}

func (r LifecycleObservation) Matches(request LifecycleReconcileRequest) bool {
	return r.Valid() && r.TaskID == request.TaskID && r.InstanceID == request.InstanceID && r.Epoch == request.Epoch && r.Fencing == request.Fencing && r.OriginalTaskID == request.Original.TaskID &&
		(r.Receipt == nil || (r.Receipt.Kind == request.Original.Kind && r.Receipt.Fencing == request.Original.Fencing))
}

func lifecyclePublicationError(r LifecycleReconcileRequest, state State, journal *Journal) string {
	if state.InstanceID != r.InstanceID || state.Epoch != r.Epoch || state.Fencing >= r.Original.Fencing {
		return "stale_lifecycle_observation"
	}
	if journal != nil && (journal.Epoch != r.Epoch || journal.Fencing >= r.Original.Fencing || journal.State != "committed" || journal.Fencing != state.Fencing || journal.Generation != state.Generation || journal.TaskID != state.LastTaskID || journal.CandidateVersion != state.CurrentVersion || state.CurrentVersion == "") {
		return "singbox_recovery_required"
	}
	return ""
}

// This metadata revokes delayed execution authority without rewriting an
// operation receipt, lifecycle fence, publication state or runtime files.
type lifecycleReconcileAuthority struct {
	TaskID          string `json:"task_id"`
	InstanceID      string `json:"instance_id"`
	Epoch           string `json:"epoch"`
	Fencing         uint64 `json:"fencing"`
	OriginalTaskID  string `json:"original_task_id"`
	OriginalFencing uint64 `json:"original_fencing"`
}

func (a lifecycleReconcileAuthority) valid() bool {
	return lifecycleID.MatchString(a.TaskID) && lifecycleID.MatchString(a.InstanceID) && lifecycleID.MatchString(a.Epoch) && lifecycleID.MatchString(a.OriginalTaskID) && a.TaskID != a.OriginalTaskID && a.OriginalFencing > 0 && a.Fencing > a.OriginalFencing && a.Fencing < 1<<63
}

func (a lifecycleReconcileAuthority) permitsObservation(r LifecycleReconcileRequest) bool {
	if !a.valid() || a.InstanceID != r.InstanceID || a.Epoch != r.Epoch || a.Fencing > r.Fencing {
		return false
	}
	return a.Fencing < r.Fencing || (a.TaskID == r.TaskID && a.OriginalTaskID == r.Original.TaskID && a.OriginalFencing == r.Original.Fencing)
}

func (a lifecycleReconcileAuthority) permitsLifecycle(r LifecycleRequest) bool {
	return a.valid() && a.InstanceID == r.InstanceID && a.Epoch == r.Epoch && r.Fencing > a.Fencing
}

// Exposes only observation plus durable execution-authority metadata. Original
// receipts and fences remain unchanged; the Agent persists fresh observations.
type lifecycleReconcileReader interface {
	lock(context.Context, LifecycleReconcileRequest) (func(), error)
	receipt(LifecycleRequest) (LifecycleResult, error)
	fence(string) (string, uint64, error)
	authorize(LifecycleReconcileRequest) error
	observe(context.Context, LifecycleReconcileRequest) (bool, string, string, error)
}

func reconcileLifecycle(ctx context.Context, r LifecycleReconcileRequest, reader lifecycleReconcileReader) (LifecycleObservation, error) {
	o := LifecycleObservation{TaskID: r.TaskID, InstanceID: r.InstanceID, Epoch: r.Epoch, Fencing: r.Fencing, OriginalTaskID: r.Original.TaskID, ServiceState: "unknown", ObservedAt: time.Now().UTC()}
	if !r.Valid() {
		return o, errors.New("invalid_lifecycle_reconcile_request")
	}
	fail := func(code string) (LifecycleObservation, error) {
		o.ErrorCode, o.ObservedAt = code, time.Now().UTC()
		return o, nil
	}
	unlock, err := reader.lock(ctx, r)
	if err != nil {
		return fail("lifecycle_reconcile_lock_unavailable")
	}
	defer unlock()
	receipt, err := reader.receipt(r.Original)
	if err == nil {
		o.Receipt = &receipt
		if !o.Matches(r) {
			o.Receipt = nil
			return fail("lifecycle_receipt_mismatch")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail("lifecycle_receipt_unavailable")
	}
	epoch, fencing, err := reader.fence(r.InstanceID)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fail("lifecycle_fence_unavailable")
	}
	if (epoch != "" && epoch != r.Epoch) || fencing > r.Original.Fencing {
		return fail("stale_lifecycle_observation")
	}
	if err = reader.authorize(r); err != nil {
		return fail("lifecycle_reconcile_authority_unavailable")
	}
	installed, version, state, err := reader.observe(ctx, r)
	if err != nil {
		code := err.Error()
		if !lifecycleObservationError.MatchString(code) {
			code = "lifecycle_observation_unavailable"
		}
		return fail(code)
	}
	// Removed runtime files no longer carry the deployment epoch. Require its
	// protected lifecycle fence before treating physical absence as fresh proof.
	if !installed && epoch != r.Epoch {
		return fail("lifecycle_absence_epoch_unverified")
	}
	if ctx.Err() != nil {
		return fail("lifecycle_observation_cancelled")
	}
	o.Installed, o.Version, o.ServiceState, o.ObservedAt = installed, version, state, time.Now().UTC()
	return o, nil
}
