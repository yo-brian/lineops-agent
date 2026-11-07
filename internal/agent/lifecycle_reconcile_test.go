package agent

import (
	"context"
	"encoding/json"
	"errors"
	"lineop-agent/internal/agentproto"
	"lineop-agent/internal/release"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type lifecycleReadOnlyExecutor struct {
	supported bool
	called    int
	observe   func(context.Context, release.LifecycleReconcileRequest) (release.LifecycleObservation, error)
}

func (e *lifecycleReadOnlyExecutor) Capabilities(context.Context) ([]string, []string, error) {
	if e.supported {
		return nil, []string{"singbox_reconcile_v1"}, nil
	}
	return nil, []string{"singbox_lifecycle_v1"}, nil
}
func (e *lifecycleReadOnlyExecutor) LifecycleReconcile(ctx context.Context, r release.LifecycleReconcileRequest) (release.LifecycleObservation, error) {
	e.called++
	return e.observe(ctx, r)
}
func lifecycleObservationLease() (agentproto.Lease, release.LifecycleReconcileRequest) {
	original := release.LifecycleRequest{TaskID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", InstanceID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", Epoch: "cccccccc-cccc-cccc-cccc-cccccccccccc", Kind: "restart_singbox", Fencing: 2}
	r := release.LifecycleReconcileRequest{TaskID: "dddddddd-dddd-dddd-dddd-dddddddddddd", InstanceID: original.InstanceID, Epoch: original.Epoch, Fencing: 3, Original: original}
	data, _ := json.Marshal(r)
	return agentproto.Lease{TaskID: r.TaskID, Fencing: int64(r.Fencing), Kind: "singbox_reconcile", Payload: data, Deadline: time.Now().Add(time.Minute)}, r
}
func lifecycleObserved(_ context.Context, r release.LifecycleReconcileRequest) (release.LifecycleObservation, error) {
	return release.LifecycleObservation{TaskID: r.TaskID, InstanceID: r.InstanceID, Epoch: r.Epoch, Fencing: r.Fencing, OriginalTaskID: r.Original.TaskID, Installed: true, Version: "1.14.0", ServiceState: "running", ObservedAt: time.Now()}, nil
}

func TestLifecycleObservationPersistsUnderOuterTaskBeforeSubmission(t *testing.T) {
	cmd, req := lifecycleObservationLease()
	dir := t.TempDir()
	name := "receipt-" + req.TaskID + "-3.json"
	submitted := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/results" {
			t.Error("unexpected operation", r.URL.Path)
			w.WriteHeader(500)
			return
		}
		submitted++
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Error("receipt not durable before result submission", err)
		}
		var stored receipt
		if json.Unmarshal(data, &stored) != nil || stored.TaskID != req.TaskID || stored.Fencing != 3 || stored.Lifecycle != nil || stored.LifecycleObservation == nil || !stored.LifecycleObservation.Matches(req) {
			t.Error("incorrectly bound observation receipt")
		}
		w.WriteHeader(503)
	}))
	defer server.Close()
	c := &Client{BaseURL: server.URL, HTTP: server.Client(), StateDir: dir}
	e := &lifecycleReadOnlyExecutor{supported: true, observe: lifecycleObserved}
	if err := c.executeLifecycleObservation(context.Background(), cmd, e, time.Hour); err == nil {
		t.Fatal("expected failed submission")
	}
	if submitted != 1 || e.called != 1 {
		t.Fatal(submitted, e.called)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
		t.Fatal("lost observation evidence", err)
	}
}

func TestLifecycleObservationRequiresCapabilityAndBoundIdentity(t *testing.T) {
	cmd, _ := lifecycleObservationLease()
	c := &Client{StateDir: t.TempDir()}
	e := &lifecycleReadOnlyExecutor{observe: lifecycleObserved}
	if err := c.executeLifecycleObservation(context.Background(), cmd, e, time.Hour); err == nil || e.called != 0 {
		t.Fatal("old executor accepted reconciliation")
	}
	e.supported = true
	cmd.Fencing++
	if err := c.executeLifecycleObservation(context.Background(), cmd, e, time.Hour); err == nil || e.called != 0 {
		t.Fatal("mismatched fencing accepted")
	}
}

func TestLifecycleObservationCancelsAndDrainsFailedRenewal(t *testing.T) {
	cmd, _ := lifecycleObservationLease()
	renewed := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/lease" {
			t.Error("unexpected submission after lease loss")
			w.WriteHeader(500)
			return
		}
		close(renewed)
		w.WriteHeader(409)
	}))
	defer server.Close()
	c := &Client{BaseURL: server.URL, HTTP: server.Client(), StateDir: t.TempDir()}
	e := &lifecycleReadOnlyExecutor{supported: true, observe: func(ctx context.Context, _ release.LifecycleReconcileRequest) (release.LifecycleObservation, error) {
		<-ctx.Done()
		return release.LifecycleObservation{}, ctx.Err()
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.executeLifecycleObservation(ctx, cmd, e, time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Fatal("lease loss did not cancel executor", err)
	}
	select {
	case <-renewed:
	default:
		t.Fatal("renewal not observed")
	}
	entries, _ := os.ReadDir(c.StateDir)
	if len(entries) != 0 {
		t.Fatal("invented result after cancellation")
	}
}
