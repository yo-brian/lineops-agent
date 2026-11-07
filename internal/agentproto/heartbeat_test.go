package agentproto

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"lineop-agent/internal/traffic"
	"reflect"
	"strings"
	"testing"
	"time"
)

func trafficFixture(n int) Inventory {
	i := Inventory{Hostname: "fixture", AgentVersion: "0.10.0-dev", ConfigurationState: "read_only", ProtocolState: "not_verified"}
	for j := 0; j < n; j++ {
		sum := sha256.Sum256([]byte(fmt.Sprint(j)))
		id := fmt.Sprintf("%x-%x-%x-%x-%x", sum[:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
		i.NodeTraffic = append(i.NodeTraffic, traffic.Sample{ResourceID: id, Source: "singbox-user-v1:" + strings.Repeat("a", 32), Upload: 123456789012 + uint64(j), Download: 987654321012, ObservedAt: time.Date(2026, 9, 21, 0, 0, 0, 123456789, time.UTC)})
	}
	return i
}

func TestHeartbeatDeltaRoundTrip(t *testing.T) {
	base := trafficFixture(100)
	next := base
	next.NodeTraffic = append([]traffic.Sample(nil), base.NodeTraffic...)
	for j := range next.NodeTraffic {
		next.NodeTraffic[j].ObservedAt = next.NodeTraffic[j].ObservedAt.Add(15 * time.Second)
	}
	next.NodeTraffic[2].Upload += 123
	next.NodeTraffic[3].Download = 0                                         // reset retains absolute counters
	next.NodeTraffic = append(next.NodeTraffic[:6], next.NodeTraffic[7:]...) // deletion
	next.NodeTraffic[0], next.NodeTraffic[1] = next.NodeTraffic[1], next.NodeTraffic[0]
	wire := PrepareHeartbeat(next, base.NodeTraffic, true)
	if wire.Delta == nil {
		t.Fatal("expected delta")
	}
	raw, _ := json.Marshal(wire)
	var decoded Heartbeat
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	expanded, err := ExpandHeartbeat(decoded, base.NodeTraffic)
	if err != nil || !reflect.DeepEqual(expanded, next) {
		t.Fatal("round trip lost counters, timestamp or order", err)
	}
	if !expanded.Valid() {
		t.Fatal("invalid round trip")
	}
	if _, err = ExpandHeartbeat(decoded, next.NodeTraffic); !errors.Is(err, ErrTrafficBaseline) {
		t.Fatal("stale baseline accepted", err)
	}
	if PrepareHeartbeat(next, base.NodeTraffic, false).Delta != nil {
		t.Fatal("legacy peer received delta")
	}
}

func TestHeartbeatRejectsMalformedReferences(t *testing.T) {
	base := trafficFixture(2)
	at := time.Now()
	for _, refs := range [][]TrafficRef{{{Index: 2, At: &at}}, {{Index: 0}}, {{Index: 0, At: &at}, {Index: 0, At: &at}}, {{Index: -3}}, {{Index: -1 << 63}}} {
		if _, err := ExpandHeartbeat(Heartbeat{Inventory: base, Delta: &TrafficDelta{Base: TrafficHash(base.NodeTraffic), Refs: refs}}, base.NodeTraffic); err == nil {
			t.Fatal("accepted malformed references", refs)
		}
	}
}

func TestHeartbeatTrafficSuccessIsBoundedAndExplicitlyPartial(t *testing.T) {
	inv := Inventory{ConfigurationState: "read_only", ProtocolState: "not_verified"}
	id := "00000000-0000-0000-0000-000000000001"
	for _, h := range []Heartbeat{
		{Inventory: inv},
		{Inventory: inv, InstancePartial: true, InstanceTrafficObserved: []string{id}},
	} {
		if !h.Valid() {
			t.Fatal("valid legacy or partial heartbeat rejected")
		}
	}
	tooMany := make([]string, 101)
	for j := range tooMany {
		tooMany[j] = fmt.Sprintf("%08x-0000-0000-0000-%012x", j, j)
	}
	for _, h := range []Heartbeat{
		{Inventory: inv, InstanceTrafficObserved: []string{id}},
		{Inventory: inv, InstancePartial: true, InstanceTrafficObserved: []string{id, id}},
		{Inventory: inv, InstancePartial: true, InstanceTrafficObserved: []string{"invalid"}},
		{Inventory: inv, InstancePartial: true, InstanceTrafficObserved: tooMany},
	} {
		if h.Valid() {
			t.Fatal("invalid traffic success marker accepted")
		}
	}
}

func TestHeartbeatWireSizes(t *testing.T) {
	packed := func(b []byte) int {
		var out bytes.Buffer
		w, _ := gzip.NewWriterLevel(&out, gzip.BestSpeed)
		_, _ = w.Write(b)
		_ = w.Close()
		return out.Len()
	}
	for _, n := range []int{10, 100, 1000} {
		base := trafficFixture(n)
		next := base
		next.NodeTraffic = append([]traffic.Sample(nil), base.NodeTraffic...)
		for j := range next.NodeTraffic {
			next.NodeTraffic[j].ObservedAt = next.NodeTraffic[j].ObservedAt.Add(15 * time.Second)
		}
		for _, changed := range []int{0, 10, 100} {
			for j := range next.NodeTraffic {
				next.NodeTraffic[j].Upload = base.NodeTraffic[j].Upload
				if j < n*changed/100 {
					next.NodeTraffic[j].Upload++
				}
			}
			full, _ := json.Marshal(next)
			delta, _ := json.Marshal(PrepareHeartbeat(next, base.NodeTraffic, true))
			t.Logf("samples=%d changed=%d%% full=%d gzip_full=%d delta=%d gzip_delta=%d", n, changed, len(full), packed(full), len(delta), packed(delta))
			if n >= 100 && changed == 0 && packed(delta) >= packed(full)/2 {
				t.Fatal("unchanged samples were not reduced")
			}
		}
	}
}
