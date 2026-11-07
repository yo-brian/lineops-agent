package agent

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lineop-agent/internal/agentproto"
	"lineop-agent/internal/traffic"
)

func TestHeartbeatNegotiatesAndRecoversLostAcknowledgement(t *testing.T) {
	var base []traffic.Sample
	var requests []string
	lost := false
	rejectOptimized := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kind := "plain"
		var reader io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			kind = "gzip"
			gz, err := gzip.NewReader(reader)
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			defer gz.Close()
			reader = gz
		}
		var h agentproto.Heartbeat
		if err := json.NewDecoder(reader).Decode(&h); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if h.Delta != nil {
			kind += "+delta"
		}
		requests = append(requests, kind)
		if rejectOptimized && (kind != "plain") {
			w.WriteHeader(415)
			return
		}
		inv, err := agentproto.ExpandHeartbeat(h, base)
		if err != nil {
			w.WriteHeader(409)
			return
		}
		base = append([]traffic.Sample(nil), inv.NodeTraffic...)
		if !lost && h.Delta != nil {
			lost = true
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
			return
		}
		ack := agentproto.HeartbeatAck{Received: true}
		if !rejectOptimized {
			ack.Capabilities = []string{agentproto.HeartbeatGzip, agentproto.HeartbeatDelta}
			ack.TrafficHash = agentproto.TrafficHash(base)
		}
		_ = json.NewEncoder(w).Encode(ack)
	}))
	defer s.Close()
	c := &Client{BaseURL: s.URL, HTTP: s.Client()}
	inv := agentproto.Inventory{ConfigurationState: "read_only", ProtocolState: "not_verified"}
	for n := 0; n < 40; n++ {
		inv.NodeTraffic = append(inv.NodeTraffic, traffic.Sample{ResourceID: fmt.Sprintf("%036d", n), Source: "singbox-v1:" + strings.Repeat("a", 32), Upload: 100, ObservedAt: time.Now().UTC()})
	}
	if err := c.sendHeartbeat(context.Background(), inv); err != nil {
		t.Fatal(err)
	}
	for j := range inv.NodeTraffic {
		inv.NodeTraffic[j].ObservedAt = inv.NodeTraffic[j].ObservedAt.Add(time.Second)
	}
	if err := c.sendHeartbeat(context.Background(), inv); err == nil {
		t.Fatal("lost acknowledgement accepted")
	}
	if err := c.sendHeartbeat(context.Background(), inv); err != nil {
		t.Fatal("full resync failed", err)
	}
	if strings.Join(requests, ",") != "plain,gzip+delta,gzip+delta,plain" {
		t.Fatal(requests)
	}
	if agentproto.TrafficHash(base) != agentproto.TrafficHash(inv.NodeTraffic) {
		t.Fatal("resync lost data")
	}
	rejectOptimized = true
	if err := c.sendHeartbeat(context.Background(), inv); err != nil {
		t.Fatal("legacy fallback failed", err)
	}
	if c.heartbeatDelta || c.heartbeatGzip {
		t.Fatal("legacy peer kept optimization enabled")
	}
}

func TestHeartbeatLegacyServerAlwaysReceivesFullJSON(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") != "" {
			t.Error("gzip without negotiation")
		}
		var inv agentproto.Inventory
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&inv); err != nil {
			t.Error(err)
		}
		_, _ = io.WriteString(w, `{"received":true,"protocol_verified":false}`)
	}))
	defer s.Close()
	c := &Client{BaseURL: s.URL, HTTP: s.Client()}
	for range 3 {
		if err := c.sendHeartbeat(context.Background(), agentproto.Inventory{Hostname: strings.Repeat("a", 200)}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPartialHeartbeatPageBaselineSurvivesLostAcknowledgement(t *testing.T) {
	var base []traffic.Sample
	services := map[string]bool{}
	lost, rejected, fullRecovery := false, false, false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reader io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(reader)
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			defer gz.Close()
			reader = gz
		}
		var wire agentproto.Heartbeat
		if err := json.NewDecoder(reader).Decode(&wire); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if !wire.Valid() || !wire.InstancePartial || len(wire.Services) != 1 || len(wire.InstanceTrafficObserved) != 1 || wire.InstanceTrafficObserved[0] != wire.Services[0].InstanceID {
			t.Error("partial page or zero-sample success marker lost")
		}
		inv, err := agentproto.ExpandHeartbeat(wire, base)
		if err != nil {
			rejected = true
			w.WriteHeader(409)
			return
		}
		if rejected && wire.Delta == nil {
			fullRecovery = true
		}
		base = append([]traffic.Sample(nil), inv.NodeTraffic...)
		services[inv.Services[0].InstanceID] = true
		if wire.Delta != nil && !lost {
			lost = true
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
			return
		}
		json.NewEncoder(w).Encode(agentproto.HeartbeatAck{Received: true, Capabilities: []string{agentproto.HeartbeatGzip, agentproto.HeartbeatDelta}, TrafficHash: agentproto.TrafficHash(inv.NodeTraffic)})
	}))
	defer s.Close()
	c := &Client{BaseURL: s.URL, HTTP: s.Client()}
	page := func(n int) agentproto.Inventory {
		id := fmt.Sprintf("%08x-0000-0000-0000-%012x", n, n)
		inv := agentproto.Inventory{ConfigurationState: "read_only", ProtocolState: "not_verified", Services: []agentproto.ServiceObservation{{InstanceID: id, State: "running"}}}
		for stream := 0; stream < 40; stream++ {
			inv.NodeTraffic = append(inv.NodeTraffic, traffic.Sample{ResourceID: id, Source: fmt.Sprintf("singbox-v1:%032x", stream), Upload: 100, ObservedAt: time.Now().UTC()})
		}
		return inv
	}
	first, second := page(1), page(2)
	for _, inv := range []agentproto.Inventory{first, second} {
		if err := c.sendHeartbeatPage(context.Background(), inv, true, inv.Services[0].InstanceID); err != nil {
			t.Fatal(err)
		}
		if agentproto.TrafficHash(base) != agentproto.TrafficHash(inv.NodeTraffic) || agentproto.TrafficHash(c.acknowledgedTraffic) != agentproto.TrafficHash(inv.NodeTraffic) {
			t.Fatal("acknowledged baseline accumulated other pages")
		}
	}
	for index := range second.NodeTraffic {
		second.NodeTraffic[index].ObservedAt = second.NodeTraffic[index].ObservedAt.Add(time.Second)
	}
	if err := c.sendHeartbeatPage(context.Background(), second, true, second.Services[0].InstanceID); err == nil || !lost {
		t.Fatal("lost partial delta acknowledgement was accepted", err)
	}
	if err := c.sendHeartbeatPage(context.Background(), second, true, second.Services[0].InstanceID); err != nil || !rejected || !fullRecovery {
		t.Fatal("partial full recovery failed", rejected, fullRecovery, err)
	}
	third := page(3)
	third.NodeTraffic = nil // Successful collection can have no samples.
	if err := c.sendHeartbeatPage(context.Background(), third, true, third.Services[0].InstanceID); err != nil || len(base) != 0 || len(services) != 3 {
		t.Fatal("final page replaced previous services or retained counters", len(services), len(base), err)
	}
}
