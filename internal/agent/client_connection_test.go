package agent

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRequestReusesTLSConnectionAfterAcknowledgement(t *testing.T) {
	var connections atomic.Int32
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/commands") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = io.WriteString(w, `{"received":true,"protocol_verified":false}`)
	}))
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	s.StartTLS()
	defer s.Close()
	c := &Client{BaseURL: s.URL, HTTP: s.Client()}
	defer c.HTTP.CloseIdleConnections()
	for range 3 {
		if code, err := c.request(context.Background(), "POST", "/heartbeat", map[string]string{"hostname": "fixture"}, nil); err != nil || code != 200 {
			t.Fatal(code, err)
		}
		if code, err := c.request(context.Background(), "GET", "/commands", nil, nil); err != nil || code != 204 {
			t.Fatal(code, err)
		}
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("6 sequential requests opened %d TLS connections; want 1", got)
	}
}
