package agent

import (
	"context"
	"errors"
	"testing"

	"lineop-agent/internal/release"
)

type reconciliationProbe struct {
	stored          release.State
	err             error
	reads, verifies int
}

func (p *reconciliationProbe) Receipt(context.Context, string, string) (release.State, error) {
	p.reads++
	return p.stored, p.err
}
func (p *reconciliationProbe) VerifyStatus(context.Context, string) (release.State, error) {
	p.verifies++
	return release.State{LastTaskID: "current"}, nil
}

func TestReconcileUsesOnlyMatchingPreflightReceipt(t *testing.T) {
	for _, name := range []string{"preflight", "success", "other_failure", "other_task", "other_instance", "missing", "old_panel"} {
		t.Run(name, func(t *testing.T) {
			p := &reconciliationProbe{stored: release.State{InstanceID: "instance", LastTaskID: "original", LastResult: "failed_manual", ErrorCode: "preflight_rejected"}}
			original := "original"
			switch name {
			case "success":
				p.stored.LastResult = "succeeded"
			case "other_failure":
				p.stored.ErrorCode = "configuration_or_dependency_drift"
			case "other_task":
				p.stored.LastTaskID = "different"
			case "other_instance":
				p.stored.InstanceID = "different"
			case "missing":
				p.err = errors.New("receipt unavailable")
			case "old_panel":
				original = ""
			}
			got, err := reconcileRelease(context.Background(), p, "instance", original)
			if err != nil {
				t.Fatal(err)
			}
			if name == "preflight" {
				if got.LastTaskID != "original" || p.verifies != 0 {
					t.Fatalf("lost preflight evidence: %+v", got)
				}
			} else if got.LastTaskID != "current" || p.verifies != 1 {
				t.Fatalf("must verify current state: %+v", got)
			}
			if name == "old_panel" && p.reads != 0 {
				t.Fatal("old panel must not query an empty task")
			}
		})
	}
}
