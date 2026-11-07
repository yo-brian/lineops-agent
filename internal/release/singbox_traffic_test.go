package release

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/protobuf/encoding/protowire"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSingboxTrafficWire(t *testing.T) {
	name := "inbound>>>node-11111111-1111-4111-8111-111111111111>>>traffic>>>uplink"
	stat := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), name)
	stat = protowire.AppendVarint(protowire.AppendTag(stat, 2, protowire.VarintType), 1024)
	payload := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), stat)
	server := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.URL.Path != "/v2ray.core.app.stats.command.StatsService/QueryStats" {
			t.Error("wrong gRPC request")
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		frame := make([]byte, 5)
		binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
		w.Write(append(frame, payload...))
		w.Header().Set("Grpc-Status", "0")
	}), &http2.Server{}))
	defer server.Close()
	counters, err := querySingboxTraffic(context.Background(), strings.TrimPrefix(server.URL, "http://"))
	if err != nil || counters[name] != 1024 {
		t.Fatalf("%v %v", counters, err)
	}
	if _, err = querySingboxTraffic(context.Background(), "192.0.2.1:10000"); err == nil {
		t.Fatal("non-loopback endpoint accepted")
	}
	for _, raw := range [][]byte{{0x0a, 0xff}, append(append([]byte{}, payload...), payload...)} {
		if _, err := decodeSingboxStats(raw); err == nil {
			t.Fatal("malformed/duplicate stats accepted")
		}
	}
}

func TestSingboxTrafficConfigAndZero(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	model := Model{Nodes: []Node{{ID: id, Listen: "0.0.0.0", Port: 443}}}
	raw, err := addTrafficAPI([]byte(`{"inbounds":[]}`), id, model)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if json.Unmarshal(raw, &config) != nil {
		t.Fatal("invalid config")
	}
	if !strings.Contains(string(raw), "inbound") || !strings.Contains(string(raw), "127.") {
		t.Fatal(string(raw))
	}
	samples := singboxSamples(model, strings.Repeat("a", 32), nil, time.Now())
	if len(samples) != 1 || samples[0].Upload != 0 || samples[0].Download != 0 || !samples[0].Valid() {
		t.Fatal(samples)
	}
	listener := trafficListener(id, model)
	model.Nodes[0].Port = listener.Port
	if _, err = addTrafficAPI([]byte(`{}`), id, model); err == nil {
		t.Fatal("wildcard collision accepted")
	}
	if _, _, err = decodeTraffic([]byte(`{"nftables":[{"table":{"name":"lo_traffic_test","comment":"foreign"}}]}`), "lo_traffic_test"); err == nil {
		t.Fatal("foreign legacy table accepted")
	}
}
