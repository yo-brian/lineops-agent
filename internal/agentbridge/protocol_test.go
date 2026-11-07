package agentbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"lineops-agent/internal/agentproto"
	"lineops-agent/internal/release"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type testOperations struct {
	apply   func(context.Context, release.Request) (release.State, error)
	verify  func(context.Context, string) (release.State, error)
	receipt func(string, string) (release.State, error)
}

func (o testOperations) VerifyStatus(ctx context.Context, id string) (release.State, error) {
	if o.verify != nil {
		return o.verify(ctx, id)
	}
	return release.State{}, errors.New("test health unavailable")
}
func (o testOperations) Receipt(id, task string) (release.State, error) {
	if o.receipt != nil {
		return o.receipt(id, task)
	}
	return release.State{}, errors.New("test receipt unavailable")
}

func (o testOperations) Apply(ctx context.Context, r release.Request) (release.State, error) {
	return o.apply(ctx, r)
}
func (testOperations) UpdatePolicies(context.Context, string, release.PolicySet) (release.State, error) {
	return release.State{}, nil
}
func (testOperations) Status(id string) (release.State, error) {
	return release.State{InstanceID: id, LastResult: "unpublished"}, nil
}
func TestExecutorStrictTypedBoundary(t *testing.T) {
	calls := 0
	h := &handler{engine: testOperations{apply: func(context.Context, release.Request) (release.State, error) { calls++; return release.State{}, nil }}, validateRegistration: func(string) error { return nil }, active: make(chan struct{}, 4)}
	for _, body := range []string{`{"instance_id":"../etc"}`, `{"instance_id":"registered","root":"/etc"}`, `{"instance_id":"registered"} {}`, `{"instance_id":"registered","command":"sh"}`} {
		r := httptest.NewRequest("POST", "/v1/apply", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code < 400 {
			t.Fatal("unsafe typed request accepted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid request reached engine")
	}
}
func TestExecutorAcceptedReleaseSurvivesClientCancellation(t *testing.T) {
	started := make(chan struct{})
	finish := make(chan struct{})
	h := &handler{engine: testOperations{apply: func(ctx context.Context, r release.Request) (release.State, error) {
		close(started)
		<-finish
		if ctx.Err() != nil {
			t.Error("client cancellation aborted release")
		}
		return release.State{InstanceID: r.InstanceID, LastResult: "failed_rolled_back"}, errors.New("publication failed; previous service safely restored")
	}}, validateRegistration: func(string) error { return nil }, active: make(chan struct{}, 1)}
	body, _ := json.Marshal(release.Request{InstanceID: "registered"})
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest("POST", "/v1/apply", bytes.NewReader(body)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { h.ServeHTTP(response, request); close(done) }()
	<-started
	cancel()
	close(finish)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("executor did not finish")
	}
	var result Response
	if e := json.Unmarshal(response.Body.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	if response.Code != 409 || result.State.LastResult != "failed_rolled_back" || result.ErrorCode != "failed_rolled_back" {
		t.Fatal("failure evidence lost")
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestExecutorClientKeepsFailureState(t *testing.T) {
	c := &Client{http: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 409, Body: io.NopCloser(strings.NewReader(`{"state":{"instance_id":"registered","last_result":"failed_rolled_back"},"error_code":"failed_rolled_back"}`))}, nil
	})}}
	state, e := c.Apply(context.Background(), release.Request{})
	if e == nil || state.LastResult != "failed_rolled_back" {
		t.Fatal("client lost business failure evidence")
	}
}

func TestExecutorVerifyBoundAndReadyRemainsAvailable(t *testing.T) {
	started := make(chan struct{}, 2)
	finish := make(chan struct{})
	h := &handler{engine: testOperations{verify: func(context.Context, string) (release.State, error) {
		started <- struct{}{}
		<-finish
		return release.State{InstanceID: "registered", LastResult: "succeeded"}, nil
	}}, validateRegistration: func(string) error { return nil }, active: make(chan struct{}, 4), verifying: make(chan struct{}, 2)}
	call := func(path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	var wait sync.WaitGroup
	for i := 0; i < 2; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if w := call("/v1/verify-status", `{"instance_id":"registered"}`); w.Code != 200 {
				t.Error("verification unexpectedly failed")
			}
		}()
	}
	<-started
	<-started
	if w := call("/v1/verify-status", `{"instance_id":"registered"}`); w.Code != 429 {
		t.Error("verification concurrency not bounded")
	}
	if w := call("/v1/ready", `{}`); w.Code != 200 {
		t.Error("Ready blocked behind slow verification")
	} else {
		var response Response
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || len(response.Templates) != 5 || response.Templates[1] != release.MultiProtocolTemplate || response.Templates[4] != release.TeamSSTemplate {
			t.Fatal("executor capabilities missing", err)
		}
		inventory := agentproto.Inventory{ReleaseExecutor: true, ReleaseTemplates: response.Templates, ConfigurationState: "read_only", ProtocolState: "not_verified"}
		if !inventory.Valid() {
			close(finish)
			wait.Wait()
			t.Fatal("panel rejects capabilities advertised by the actual executor")
		}
	}
	if w := call("/v1/status", `{"instance_id":"registered"}`); w.Code != 200 {
		t.Error("Status blocked behind slow verification")
	}
	close(finish)
	wait.Wait()
}
func TestExecutorVerifyFailureAndIndependentReceipt(t *testing.T) {
	h := &handler{engine: testOperations{verify: func(context.Context, string) (release.State, error) {
		return release.State{InstanceID: "registered", LastTaskID: "new-task", LastResult: "succeeded"}, errors.New("health failed")
	}, receipt: func(id, task string) (release.State, error) {
		return release.State{InstanceID: id, LastTaskID: task, LastResult: "failed_rolled_back", Generation: 1, Fencing: 1}, nil
	}}, validateRegistration: func(string) error { return nil }, verifying: make(chan struct{}, 2)}
	call := func(path, body string) (int, Response) {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var response Response
		if e := json.Unmarshal(w.Body.Bytes(), &response); e != nil {
			t.Fatal(e)
		}
		return w.Code, response
	}
	status, response := call("/v1/verify-status", `{"instance_id":"registered"}`)
	if status != 409 || response.State.LastResult != "unknown" || response.ErrorCode == "" {
		t.Fatal("failed health reused old succeeded state")
	}
	status, response = call("/v1/receipt", `{"instance_id":"registered","task_id":"old-task"}`)
	if status != 200 || response.State.LastTaskID != "old-task" || response.State.LastResult != "failed_rolled_back" {
		t.Fatal("independent receipt was replaced with latest status")
	}
	for _, body := range []string{`{"instance_id":"registered","task_id":"../state"}`, `{"instance_id":"registered","task_id":"old-task","path":"/etc"}`, `{"instance_id":"registered","task_id":"old-task"}{}`} {
		if status, _ = call("/v1/receipt", body); status < 400 {
			t.Fatal("unsafe receipt request accepted")
		}
	}
}
