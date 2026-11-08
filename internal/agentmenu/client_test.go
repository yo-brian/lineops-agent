package agentmenu

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPanelClientSecurityAndErrors(t *testing.T) {
	for _, url := range []string{"http://panel.test", "https://user:pass@panel.test", "https://panel.test/path", "https://panel.test?q=x", "https://panel.test#x"} {
		if _, e := newClient(url, ""); e == nil {
			t.Fatalf("accepted %s", url)
		}
	}
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != server.URL || r.Header.Get("Authorization") != "Bearer machine-token" {
			t.Error("missing origin/bearer identity")
		}
		if r.Method == "POST" && r.Header.Get("Idempotency-Key") == "" {
			t.Error("missing idempotency key")
		}
		switch r.URL.Path {
		case "/api/v1/agent/menu/redirect":
			http.Redirect(w, r, "https://other.test", 302)
		case "/api/v1/agent/menu/expired":
			w.WriteHeader(401)
			w.Write([]byte(`{"error":{"message":"会话过期","code":"unauthorized"}}`))
		default:
			w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer server.Close()
	p, e := newClient(server.URL, "")
	if e != nil {
		t.Fatal(e)
	}
	p.http.Transport = server.Client().Transport
	p.token = "machine-token"
	var out object
	if e = p.call("POST", "/test", object{}, &out); e != nil || out["ok"] != true {
		t.Fatal(out, e)
	}
	if e = p.call("POST", "/redirect", object{}, nil); e == nil {
		t.Fatal("redirect followed")
	}
	if e = p.call("GET", "/expired", nil, nil); e == nil || !strings.Contains(e.Error(), "会话过期") || p.token != "" {
		t.Fatal("rejected identity not cleared", e)
	}
}
