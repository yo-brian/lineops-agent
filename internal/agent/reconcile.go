package agent

import (
	"context"
	"time"

	"lineops-agent/internal/release"
)

type reconciliationExecutor interface {
	Receipt(context.Context, string, string) (release.State, error)
	VerifyStatus(context.Context, string) (release.State, error)
}

// A preflight rejection belongs to the attempted publication, while current
// state still belongs to the previous release. Never substitute a historical
// success for a fresh health check. The panel validates the complete receipt
// identity against the original publication before accepting any outcome.
func reconcileRelease(ctx context.Context, executor reconciliationExecutor, instance, original string) (release.State, error) {
	if original != "" {
		probe, cancel := context.WithTimeout(ctx, 3*time.Second)
		state, err := executor.Receipt(probe, instance, original)
		cancel()
		if err == nil && state.InstanceID == instance && state.LastTaskID == original && state.LastResult == "failed_manual" && state.ErrorCode == "preflight_rejected" {
			return state, nil
		}
	}
	// Missing receipts and older panel payloads retain fresh verification.
	return executor.VerifyStatus(ctx, instance)
}
