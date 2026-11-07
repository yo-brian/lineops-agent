package release

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func observationRequest() LifecycleReconcileRequest {
	original := LifecycleRequest{TaskID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", InstanceID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", Epoch: "cccccccc-cccc-cccc-cccc-cccccccccccc", Kind: "restart_singbox", Fencing: 4}
	return LifecycleReconcileRequest{TaskID: "dddddddd-dddd-dddd-dddd-dddddddddddd", InstanceID: original.InstanceID, Epoch: original.Epoch, Fencing: 6, Original: original}
}

type observationReader struct {
	authorityErr                              error
	authorityCalls                            int
	stored                                    LifecycleResult
	receiptErr, lockErr, observeErr, fenceErr error
	epoch                                     string
	fencing                                   uint64
	installed                                 bool
	state, version                            string
	reads, observed, unlocked                 int
}

func (p *observationReader) lock(context.Context, LifecycleReconcileRequest) (func(), error) {
	return func() { p.unlocked++ }, p.lockErr
}
func (p *observationReader) receipt(LifecycleRequest) (LifecycleResult, error) {
	p.reads++
	return p.stored, p.receiptErr
}
func (p *observationReader) fence(string) (string, uint64, error) {
	return p.epoch, p.fencing, p.fenceErr
}
func (p *observationReader) authorize(LifecycleReconcileRequest) error {
	p.authorityCalls++
	return p.authorityErr
}
func (p *observationReader) observe(context.Context, LifecycleReconcileRequest) (bool, string, string, error) {
	p.observed++
	return p.installed, p.version, p.state, p.observeErr
}

func TestLifecycleReconcilePreservesHistoricalReceiptSeparately(t *testing.T) {
	r := observationRequest()
	for _, historical := range []string{"missing", "unknown", "succeeded", "failed_manual"} {
		t.Run(historical, func(t *testing.T) {
			p := &observationReader{installed: true, version: "1.14.0", state: "running", epoch: r.Epoch, fencing: r.Original.Fencing}
			p.stored = LifecycleResult{TaskID: r.Original.TaskID, InstanceID: r.InstanceID, Epoch: r.Epoch, Kind: r.Original.Kind, Fencing: r.Original.Fencing, State: historical, ServiceState: "unknown", FinishedAt: time.Now()}
			if historical == "missing" {
				p.receiptErr = os.ErrNotExist
			}
			original := p.stored
			got, err := reconcileLifecycle(context.Background(), r, p)
			if err != nil || !got.Matches(r) || got.ErrorCode != "" || got.ServiceState != "running" || p.observed != 1 || p.unlocked != 1 {
				t.Fatalf("observation failed: %+v %v", got, err)
			}
			if historical == "missing" && got.Receipt != nil {
				t.Fatal("invented historical receipt")
			}
			if historical != "missing" && (got.Receipt == nil || *got.Receipt != original) {
				t.Fatal("fresh state rewrote historical outcome")
			}
			if p.stored != original {
				t.Fatal("stored historical evidence changed")
			}
		})
	}
}

func TestLifecycleReconcileRejectsAmbiguousEvidence(t *testing.T) {
	r := observationRequest()
	for _, scenario := range []string{"lock", "corrupt_receipt", "wrong_receipt", "newer_fence", "epoch", "missing_absence_epoch", "corrupt_fence", "corrupt_authority", "partial_removal", "unhealthy", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			p := &observationReader{receiptErr: os.ErrNotExist, epoch: r.Epoch, fencing: r.Original.Fencing, state: "not_installed"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			expectedObservations := 0
			switch scenario {
			case "lock":
				p.lockErr = errors.New("busy")
			case "corrupt_receipt":
				p.receiptErr = errors.New("corrupt")
			case "wrong_receipt":
				p.receiptErr = nil
			case "newer_fence":
				p.fencing++ // Older than this reconcile lease, newer than ORIGINAL.
			case "epoch":
				p.epoch = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
			case "missing_absence_epoch":
				p.epoch, p.fencing, p.fenceErr = "", 0, os.ErrNotExist
				expectedObservations = 1
			case "corrupt_fence":
				p.fenceErr = errors.New("corrupt")
			case "corrupt_authority":
				p.authorityErr = errors.New("corrupt")
			case "partial_removal":
				p.observeErr = errors.New("singbox_absence_unverified")
				expectedObservations = 1
			case "unhealthy":
				p.observeErr = errors.New("fresh_protocol_health_failed")
				expectedObservations = 1
			case "cancelled":
				cancel()
				expectedObservations = 1
			}
			got, err := reconcileLifecycle(ctx, r, p)
			if err != nil || !got.Matches(r) || got.ErrorCode == "" || got.ServiceState != "unknown" || p.observed != expectedObservations {
				t.Fatalf("ambiguous evidence accepted: %+v %v", got, err)
			}
		})
	}
}

func TestLifecycleObservationRequiresIndependentAuthorityAndMatchingReceipt(t *testing.T) {
	r := observationRequest()
	for _, change := range []func(*LifecycleReconcileRequest){func(r *LifecycleReconcileRequest) { r.TaskID = r.Original.TaskID }, func(r *LifecycleReconcileRequest) { r.Fencing = r.Original.Fencing }, func(r *LifecycleReconcileRequest) { r.Epoch = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee" }} {
		bad := r
		change(&bad)
		if bad.Valid() {
			t.Fatal("invalid read-only authority accepted")
		}
	}
	p := &observationReader{receiptErr: os.ErrNotExist, fenceErr: os.ErrNotExist, installed: true, version: "1.14.0", state: "stopped"}
	got, _ := reconcileLifecycle(context.Background(), r, p)
	if !got.Matches(r) || got.ServiceState != "stopped" {
		t.Fatal(got)
	}
	got.Receipt = &LifecycleResult{TaskID: r.Original.TaskID, InstanceID: r.InstanceID, Epoch: r.Epoch, Kind: "uninstall_singbox", Fencing: r.Original.Fencing, State: "succeeded", FinishedAt: time.Now()}
	if got.Matches(r) {
		t.Fatal("receipt for different intent accepted")
	}
	got.Receipt = nil
	got.ErrorCode = "drift"
	if got.Valid() {
		t.Fatal("failed fresh probe marked verified")
	}
}

func TestLifecycleObservationRejectsPublicationConflicts(t *testing.T) {
	r := observationRequest()
	good := State{InstanceID: r.InstanceID, Epoch: r.Epoch, Fencing: 2, CurrentVersion: "version", LastTaskID: "publication"}
	committed := Journal{Epoch: r.Epoch, Fencing: 2, TaskID: "publication", CandidateVersion: "version", State: "committed"}
	if code := lifecyclePublicationError(r, good, &committed); code != "" {
		t.Fatal(code)
	}
	for _, scenario := range []string{"epoch", "newer_publication", "prepared", "switched", "recovering", "failed_manual", "different_version", "different_task", "different_fence", "different_generation", "unpublished_journal"} {
		s, j := good, committed
		switch scenario {
		case "epoch":
			s.Epoch = "different"
		case "newer_publication":
			s.Fencing = r.Original.Fencing
		case "prepared", "switched", "recovering", "failed_manual":
			j.State = scenario
		case "different_version":
			j.CandidateVersion = "other"
		case "different_task":
			j.TaskID = "other"
		case "different_fence":
			j.Fencing = 3
		case "different_generation":
			j.Generation++
		case "unpublished_journal":
			s.CurrentVersion = ""
			j.CandidateVersion = ""
		}
		if lifecyclePublicationError(r, s, &j) == "" {
			t.Fatal("conflicting publication passed", scenario)
		}
	}
}
