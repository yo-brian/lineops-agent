package agentbridge

import (
	"context"
	"encoding/json"
	"io"
	"lineop-agent/internal/release"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type lifecycleObservationFake struct {
	lifecycleFake
	observations *int
	cancelled    *bool
}

type observationTransport func(*http.Request) (*http.Response, error)

func (f observationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLifecycleReconcileClientRejectsMismatchedEvidence(t *testing.T) {
	original := release.LifecycleRequest{TaskID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", InstanceID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", Epoch: "cccccccc-cccc-cccc-cccc-cccccccccccc", Kind: "restart_singbox", Fencing: 1}
	r := release.LifecycleReconcileRequest{TaskID: "dddddddd-dddd-dddd-dddd-dddddddddddd", InstanceID: original.InstanceID, Epoch: original.Epoch, Fencing: 2, Original: original}
	good := release.LifecycleObservation{TaskID: r.TaskID, InstanceID: r.InstanceID, Epoch: r.Epoch, Fencing: r.Fencing, OriginalTaskID: original.TaskID, Installed: true, Version: "1.14.0", ServiceState: "running", ObservedAt: time.Now()}
	for _, scenario := range []string{"valid", "task", "fence", "epoch", "receipt_kind", "trailing_json"} {
		t.Run(scenario, func(t *testing.T) {
			value := good
			switch scenario {
			case "task":
				value.TaskID = original.TaskID
			case "fence":
				value.Fencing++
			case "epoch":
				value.Epoch = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
			case "receipt_kind":
				value.Receipt = &release.LifecycleResult{TaskID: original.TaskID, InstanceID: original.InstanceID, Epoch: original.Epoch, Fencing: original.Fencing, Kind: "uninstall_singbox", State: "succeeded", FinishedAt: time.Now()}
			}
			raw, _ := json.Marshal(value)
			if scenario == "trailing_json" {
				raw = append(raw, []byte("{}")...)
			}
			client := &Client{http: &http.Client{Transport: observationTransport(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path != "/v1/singbox/reconcile" {
					t.Fatal("wrong operation")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw))), Header: http.Header{}}, nil
			})}}
			_, err := client.LifecycleReconcile(context.Background(), r)
			if (err == nil) != (scenario == "valid") {
				t.Fatal("unexpected evidence acceptance", scenario, err)
			}
		})
	}
}

func (f lifecycleObservationFake) LifecycleReconcile(ctx context.Context, r release.LifecycleReconcileRequest) (release.LifecycleObservation, error) {
	*f.observations++
	*f.cancelled = ctx.Err() != nil
	return release.LifecycleObservation{TaskID: r.TaskID, InstanceID: r.InstanceID, Epoch: r.Epoch, Fencing: r.Fencing, OriginalTaskID: r.Original.TaskID, Installed: true, Version: "1.14.0", ServiceState: "running", ObservedAt: time.Now()}, nil
}
func TestLifecycleReconcileBoundaryNeverCallsLifecycle(t *testing.T) {
	mutations, observations, cancelled := 0, 0, false
	h := &handler{engine: lifecycleObservationFake{lifecycleFake: lifecycleFake{calls: &mutations}, observations: &observations, cancelled: &cancelled}, active: make(chan struct{}, 1)}
	original := release.LifecycleRequest{TaskID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", InstanceID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", Epoch: "cccccccc-cccc-cccc-cccc-cccccccccccc", Kind: "restart_singbox", Fencing: 1}
	r := release.LifecycleReconcileRequest{TaskID: "dddddddd-dddd-dddd-dddd-dddddddddddd", InstanceID: original.InstanceID, Epoch: original.Epoch, Fencing: 2, Original: original}
	b, _ := json.Marshal(r)
	for _, body := range []string{string(b), strings.TrimSuffix(string(b), "}") + `,"command":"restart"}`, strings.Replace(string(b), `"fencing":2`, `"fencing":1`, 1)} {
		req := httptest.NewRequest("POST", "/v1/singbox/reconcile", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if body == string(b) {
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
		} else if w.Code != 400 {
			t.Fatal("invalid authority or command accepted", w.Code)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest("POST", "/v1/singbox/reconcile", strings.NewReader(string(b))).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if mutations != 0 || observations != 2 || !cancelled {
		t.Fatal("read-only boundary mutated state or detached cancellation", mutations, observations, cancelled)
	}
}

func TestLifecycleReconcileCapabilityRequiresImplementation(t *testing.T) {
	mutations, observations, cancelled := 0, 0, false
	for _, supported := range []bool{false, true} {
		var engine operations = lifecycleFake{calls: &mutations}
		if supported {
			engine = lifecycleObservationFake{lifecycleFake: lifecycleFake{calls: &mutations}, observations: &observations, cancelled: &cancelled}
		}
		h := &handler{engine: engine}
		req := httptest.NewRequest("POST", "/v1/ready", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 200 || strings.Contains(w.Body.String(), "singbox_reconcile_v1") != supported {
			t.Fatal("capability incorrectly advertised", w.Body.String())
		}
	}
}
