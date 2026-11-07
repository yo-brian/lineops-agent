package agentbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"lineops-agent/internal/release"
	"lineops-agent/internal/traffic"
	"net"
	"net/http"
	"time"
)

type Client struct {
	socket string
	http   *http.Client
}

type inProcessTransport struct {
	handler http.Handler
}

type memoryResponseWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (w *memoryResponseWriter) Header() http.Header { return w.header }
func (w *memoryResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *memoryResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(b)
}

func (t inProcessTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := &memoryResponseWriter{header: make(http.Header)}
	t.handler.ServeHTTP(rec, req)
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	return &http.Response{
		StatusCode:    rec.status,
		Header:        rec.header,
		Body:          io.NopCloser(bytes.NewReader(rec.body.Bytes())),
		ContentLength: int64(rec.body.Len()),
		Request:       req,
	}, nil
}

func New(socket string) (*Client, error) { return NewClient(socket) }
func NewClient(socket string) (*Client, error) {
	if socket == "" {
		socket = DefaultSocket
	}
	if e := validateSocket(socket); e != nil {
		return nil, e
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		if e := validateSocket(socket); e != nil {
			return nil, e
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	return &Client{socket: socket, http: &http.Client{Transport: transport, Timeout: 7 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return &Error{Code: "redirect_forbidden"} }}}, nil
}
func (c *Client) call(ctx context.Context, path string, body any, supported ...*[]string) (release.State, error) {
	var result Response
	data, e := json.Marshal(body)
	if e != nil || len(data) > MaxRequestBytes {
		return result.State, &Error{Code: "request_limits_exceeded"}
	}
	request, e := http.NewRequestWithContext(ctx, "POST", "http://lineops-executor"+path, bytes.NewReader(data))
	if e != nil {
		return result.State, &Error{Code: "invalid_request"}
	}
	request.Header.Set("Content-Type", "application/json")
	response, e := c.http.Do(request)
	if e != nil {
		return result.State, &Error{Code: "transport_failure", Unknown: path == "/v1/apply" || path == "/v1/policy"}
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if e != nil || json.Unmarshal(raw, &result) != nil {
		return result.State, &Error{Code: "invalid_response", Unknown: path == "/v1/apply" || path == "/v1/policy"}
	}
	if response.StatusCode != 200 || result.ErrorCode != "" {
		if result.ErrorCode == "" {
			result.ErrorCode = "executor_rejected"
		}
		return result.State, &Error{Code: result.ErrorCode, Unknown: result.ErrorCode == "operation_failed" || result.ErrorCode == "receipt_unavailable" || path == "/v1/verify-status" || result.State.LastResult == "verifying"}
	}
	if len(supported) > 0 {
		*supported[0] = result.Templates
	}
	if len(supported) > 1 {
		*supported[1] = result.Capabilities
	}
	return result.State, nil
}
func (c *Client) SupportedTemplates(ctx context.Context) ([]string, error) {
	var templates []string
	_, err := c.call(ctx, "/v1/ready", struct{}{}, &templates)
	return templates, err
}
func (c *Client) Apply(ctx context.Context, r release.Request) (release.State, error) {
	return c.call(ctx, "/v1/apply", r)
}
func (c *Client) Policies(ctx context.Context, id string, p release.PolicySet) (release.State, error) {
	return c.call(ctx, "/v1/policy", PolicyRequest{InstanceID: id, Policies: p})
}
func (c *Client) Status(ctx context.Context, id string) (release.State, error) {
	return c.call(ctx, "/v1/status", StatusRequest{InstanceID: id})
}
func (c *Client) Ready(ctx context.Context) error {
	_, e := c.call(ctx, "/v1/ready", struct{}{})
	return e
}
func (c *Client) VerifyStatus(ctx context.Context, id string) (release.State, error) {
	return c.call(ctx, "/v1/verify-status", StatusRequest{InstanceID: id})
}
func (c *Client) Receipt(ctx context.Context, id, taskID string) (release.State, error) {
	return c.call(ctx, "/v1/receipt", ReceiptRequest{InstanceID: id, TaskID: taskID})
}

func (c *Client) Traffic(ctx context.Context, id string) ([]traffic.Sample, error) {
	data, _ := json.Marshal(StatusRequest{InstanceID: id})
	req, err := http.NewRequestWithContext(ctx, "POST", "http://lineops-executor/v1/traffic", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var result Response
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(raw, &result) != nil || len(result.Traffic) > 4096 {
		return nil, &Error{Code: "invalid_traffic"}
	}
	if response.StatusCode != 200 {
		return nil, &Error{Code: result.ErrorCode}
	}
	for _, sample := range result.Traffic {
		if !sample.Valid() {
			return nil, &Error{Code: "invalid_traffic"}
		}
	}
	return result.Traffic, nil
}
