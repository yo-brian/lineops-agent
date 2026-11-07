package agentbridge

import (
	"context"
	"encoding/json"
	"lineops-agent/internal/release"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type lifecycleFake struct {
	testOperations
	calls *int
}

func (f lifecycleFake) Lifecycle(_ context.Context, r release.LifecycleRequest) (release.LifecycleResult, error) {
	*f.calls++
	return release.LifecycleResult{TaskID: r.TaskID, InstanceID: r.InstanceID, Epoch: r.Epoch, Kind: r.Kind, Fencing: r.Fencing, State: "succeeded", FinishedAt: time.Now()}, nil
}
func (f lifecycleFake) LifecycleReceipt(r release.LifecycleRequest) (release.LifecycleResult, error) {
	return release.LifecycleResult{TaskID: r.TaskID, InstanceID: r.InstanceID, Epoch: r.Epoch, Kind: r.Kind, Fencing: r.Fencing, State: "unknown", FinishedAt: time.Now()}, nil
}
func TestLifecycleBoundaryAndReadOnlyReceipt(t *testing.T) {
	calls := 0
	h := &handler{engine: lifecycleFake{calls: &calls}, active: make(chan struct{}, 1)}
	r := release.LifecycleRequest{TaskID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", InstanceID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", Epoch: "cccccccc-cccc-cccc-cccc-cccccccccccc", Kind: "install_singbox", Fencing: 2}
	b, _ := json.Marshal(r)
	for _, path := range []string{"/v1/singbox", "/v1/singbox/receipt"} {
		req := httptest.NewRequest("POST", path, strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if calls != 1 {
		t.Fatal("receipt lookup executed an operation")
	}
	malicious := strings.TrimSuffix(string(b), "}") + `,"command":"sh"}`
	req := httptest.NewRequest("POST", "/v1/singbox", strings.NewReader(malicious))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 400 || calls != 1 {
		t.Fatal("untyped command crossed privilege boundary")
	}
}
