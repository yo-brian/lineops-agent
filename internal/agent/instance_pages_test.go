package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"lineops-agent/internal/agentproto"
)

func TestInstancePagesProduceBoundedExplicitHeartbeats(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint("legacy_", legacy), func(t *testing.T) {
			var ids []string
			for n := 0; n < 201; n++ {
				ids = append(ids, fmt.Sprintf("%08x-0000-0000-0000-%012x", n, n))
			}
			pages, heartbeats := 0, 0
			seen := map[string]bool{}
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer scoped-token" {
					t.Error("identity missing")
				}
				if r.URL.Path == "/api/v1/agent/instances" {
					pages++
					start := 0
					if after := r.URL.Query().Get("after"); after != "" {
						for index, id := range ids {
							if id == after {
								start = index + 1
							}
						}
					}
					end := min(start+100, len(ids))
					items := []map[string]string{}
					for _, id := range ids[start:end] {
						items = append(items, map[string]string{"id": id})
					}
					result := map[string]any{"items": items}
					if !legacy {
						result["observation_mode"] = agentproto.InstanceObservations
						result["has_more"] = end < len(ids)
						if end < len(ids) {
							result["next_cursor"] = ids[end-1]
						}
					}
					json.NewEncoder(w).Encode(result)
					return
				}
				heartbeats++
				var wire agentproto.Heartbeat
				if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
					t.Error(err)
				}
				if !wire.Inventory.Valid() || len(wire.Services) > 100 || wire.InstancePartial == legacy {
					t.Error("invalid heartbeat page", len(wire.Services), wire.InstancePartial)
				}
				for _, service := range wire.Services {
					if seen[service.InstanceID] {
						t.Error("duplicate instance")
					}
					seen[service.InstanceID] = true
				}
				json.NewEncoder(w).Encode(agentproto.HeartbeatAck{Received: true})
			}))
			defer s.Close()
			c := &Client{BaseURL: s.URL, HTTP: s.Client(), identity: identity{Token: "scoped-token"}}
			err := c.visitInstancePages(context.Background(), func(ids []string, partial bool) error {
				inventory := agentproto.Inventory{ConfigurationState: "read_only", ProtocolState: "not_verified"}
				for _, id := range ids {
					inventory.Services = append(inventory.Services, agentproto.ServiceObservation{InstanceID: id, State: "unknown"})
				}
				return c.sendHeartbeatPage(context.Background(), inventory, partial)
			})
			if err != nil {
				t.Fatal(err)
			}
			wantPages, wantInstances := 3, 201
			if legacy {
				wantPages, wantInstances = 1, 100
			}
			if pages != wantPages || heartbeats != wantPages || len(seen) != wantInstances {
				t.Fatal("instance pagination incomplete", pages, heartbeats, len(seen))
			}
		})
	}
}

func TestLegacyInstanceOrderDoesNotRequireCursorOrdering(t *testing.T) {
	ids := []string{"ffffffff-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"}
	for _, paginated := range []bool{false, true} {
		t.Run(fmt.Sprint("paginated_", paginated), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				result := map[string]any{"items": []map[string]string{{"id": ids[0]}, {"id": ids[1]}}}
				if paginated {
					result["observation_mode"] = agentproto.InstanceObservations
				}
				json.NewEncoder(w).Encode(result)
			}))
			defer s.Close()
			c := &Client{BaseURL: s.URL, HTTP: s.Client()}
			called := false
			err := c.visitInstancePages(context.Background(), func(page []string, partial bool) error {
				called = true
				if len(page) != 2 || page[0] != ids[0] || page[1] != ids[1] || partial {
					t.Fatal("legacy order or full heartbeat changed", page, partial)
				}
				return nil
			})
			if paginated && (err == nil || called) {
				t.Fatal("unordered cursor contract accepted")
			}
			if !paginated && (err != nil || !called) {
				t.Fatal("legal legacy instance order rejected", err)
			}
		})
	}
}
