package agentmenu

import (
	"bufio"
	"encoding/json"
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

func TestDeleteOnlySelectedLocalNodeAndConfirmation(t *testing.T) {
	instance := "11111111-1111-1111-1111-111111111111"
	id := "22222222-2222-2222-2222-222222222222"
	group := "33333333-3333-3333-3333-333333333333"
	for _, tc := range []struct {
		name, input, state, instance string
		writes                       int
	}{
		{"confirm", "1\nYES\n", "enabled", instance, 1},
		{"cancel", "1\nNO\n", "enabled", instance, 0},
		{"eof", "1\n", "enabled", instance, 0},
		{"already_deleted", "1\nYES\n", "deleted", instance, 0},
		{"moved", "1\nYES\n", "enabled", group, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writes := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					json.NewEncoder(w).Encode(object{"items": []object{{"id": id, "instance_id": tc.instance, "version": 7, "desired_state": tc.state, "name": "selected"}}})
					return
				}
				writes++
				if r.URL.Path != "/api/v1/agent/menu/nodes/"+id+"/state" {
					t.Error("wrong target", r.URL.Path)
				}
				var v object
				json.NewDecoder(r.Body).Decode(&v)
				if len(v) != 2 || v["state"] != "deleted" || v["version"] != float64(7) {
					t.Error("wrong mutation", v)
				}
				w.Write([]byte(`{"task_id":"task","effective":false}`))
			}))
			defer s.Close()
			p, _ := newClient(s.URL, "")
			p.http.Transport = s.Client().Transport
			m := menu{in: bufio.NewReader(strings.NewReader(tc.input)), panel: p}
			impact := object{"nodes": []any{map[string]any{"id": id, "group_id": group, "name": "selected"}, map[string]any{"id": group, "group_id": group, "name": "preserve"}}}
			_ = m.change(instance, impact, true)
			if writes != tc.writes {
				t.Fatalf("writes=%d expected=%d", writes, tc.writes)
			}
		})
	}
}

func TestCreateUsesSelectedGroupAndVersions(t *testing.T) {
	id := "11111111-1111-1111-1111-111111111111"
	group := "33333333-3333-3333-3333-333333333333"
	writes := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/agent/menu/groups":
			json.NewEncoder(w).Encode(object{"items": []object{{"id": group, "name": "group", "customer_name": "customer"}}, "total": 1})
		case r.Method == "GET" && r.URL.Path == "/api/v1/agent/menu/groups/"+group+"/deployment":
			w.Write([]byte(`{"version":9}`))
		case r.Method == "POST" && r.URL.Path == "/api/v1/agent/menu/groups/"+group+"/nodes":
			writes++
			var v object
			json.NewDecoder(r.Body).Decode(&v)
			if v["version"] != float64(9) || v["instance_version"] != float64(7) || v["instance_id"] != id || v["protocol"] != "shadowsocks" || v["deploy"] != true {
				t.Error(v)
			}
			w.Write([]byte(`{"task_id":"queued"}`))
		default:
			t.Error("unexpected endpoint", r.URL)
			w.WriteHeader(404)
		}
	}))
	defer s.Close()
	p, _ := newClient(s.URL, "")
	p.http.Transport = s.Client().Transport
	m := menu{panel: p, in: bufio.NewReader(strings.NewReader("\n1\nnode\nnode.example.com\n12345\n1\n\nYES\n"))}
	if e := m.create(id, object{"version": 7}); e != nil {
		t.Fatal(e)
	}
	if writes != 1 {
		t.Fatal(writes)
	}
}

func TestMenuReadsEveryNodePageAndSupportsLegacyReply(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		requests := 0
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			if r.Header.Get("Authorization") != "Bearer machine-token" || r.URL.Query().Get("page_size") != "100" {
				t.Error("menu paging changed identity or page bound")
			}
			page := requests
			items := []object{}
			for n := (page - 1) * 100; n < min(page*100, 201); n++ {
				items = append(items, object{"id": n})
			}
			result := object{"items": items}
			if !legacy {
				result["total"] = 201
			}
			json.NewEncoder(w).Encode(result)
		}))
		p, _ := newClient(s.URL, "")
		p.http.Transport = s.Client().Transport
		p.token = "machine-token"
		items, err := p.nodes("33333333-3333-3333-3333-333333333333")
		s.Close()
		wantPages, wantItems := 3, 201
		if legacy {
			wantPages, wantItems = 1, 100
		}
		if err != nil || requests != wantPages || len(items) != wantItems {
			t.Fatal("menu pagination incomplete", requests, len(items), err)
		}
	}
}
