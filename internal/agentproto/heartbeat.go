package agentproto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"lineop-agent/internal/traffic"
)

const HeartbeatGzip = "gzip"
const HeartbeatDelta = "traffic-delta-v1"
const InstanceObservations = "instance-observations-v1"

var ErrTrafficBaseline = errors.New("traffic baseline mismatch")

// Inventory fields remain at the top level for the legacy full-heartbeat shape.
type Heartbeat struct {
	Inventory
	Delta                   *TrafficDelta `json:"node_traffic_delta,omitempty"`
	InstancePartial         bool          `json:"instance_observations_partial,omitempty"`
	InstanceTrafficObserved []string      `json:"instance_traffic_observed,omitempty"`
}

// Successful traffic reads are independent of service and configuration probes.
// An explicit bounded list also represents successful reads with zero samples.
func (h Heartbeat) Valid() bool {
	if !h.Inventory.Valid() || len(h.InstanceTrafficObserved) > 100 || (!h.InstancePartial && len(h.InstanceTrafficObserved) > 0) {
		return false
	}
	seen := map[string]bool{}
	for _, id := range h.InstanceTrafficObserved {
		if len(id) != 36 || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

type TrafficDelta struct {
	Base string       `json:"base"`
	Refs []TrafficRef `json:"refs"`
}

// Positive indexes reference acknowledged counters; only observation time changes.
// Negative indexes reference the new, absolute samples in Inventory.NodeTraffic.
type TrafficRef struct {
	Index int        `json:"i"`
	At    *time.Time `json:"at,omitempty"`
}

type HeartbeatAck struct {
	Received         bool     `json:"received"`
	ProtocolVerified bool     `json:"protocol_verified"`
	Capabilities     []string `json:"heartbeat_capabilities,omitempty"`
	TrafficHash      string   `json:"node_traffic_hash,omitempty"`
}

func TrafficHash(samples []traffic.Sample) string {
	if len(samples) == 0 {
		samples = nil
	}
	data, _ := json.Marshal(samples)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// References preserve order, removals and fresh timestamps, never infer zero use.
// Changed counters stay absolute so a retry cannot add a byte delta twice.
func PrepareHeartbeat(current Inventory, base []traffic.Sample, allowDelta bool) Heartbeat {
	full := Heartbeat{Inventory: current}
	if !allowDelta || len(base) == 0 {
		return full
	}
	type key struct{ ID, Source string }
	indexes := map[key]int{}
	for i, s := range base {
		indexes[key{s.ResourceID, s.Source}] = i
	}
	delta := Heartbeat{Inventory: current, Delta: &TrafficDelta{Base: TrafficHash(base)}}
	delta.NodeTraffic = nil
	used := map[int]bool{}
	for _, s := range current.NodeTraffic {
		i, ok := indexes[key{s.ResourceID, s.Source}]
		if ok && !used[i] && s.Upload == base[i].Upload && s.Download == base[i].Download {
			at := s.ObservedAt
			delta.Delta.Refs = append(delta.Delta.Refs, TrafficRef{Index: i, At: &at})
			used[i] = true
		} else {
			delta.NodeTraffic = append(delta.NodeTraffic, s)
			delta.Delta.Refs = append(delta.Delta.Refs, TrafficRef{Index: -len(delta.NodeTraffic)})
		}
	}
	plain, _ := json.Marshal(full)
	encoded, _ := json.Marshal(delta)
	if len(encoded) >= len(plain) {
		return full
	}
	return delta
}

func ExpandHeartbeat(h Heartbeat, base []traffic.Sample) (Inventory, error) {
	if h.Delta == nil {
		return h.Inventory, nil
	}
	if len(h.Delta.Base) != 64 || h.Delta.Base != TrafficHash(base) {
		return Inventory{}, ErrTrafficBaseline
	}
	if len(h.Delta.Refs) > 3000 || len(h.NodeTraffic) > 3000 {
		return Inventory{}, errors.New("too many traffic references")
	}
	result := h.Inventory
	result.NodeTraffic = nil
	used := map[int]bool{}
	changed := 0
	for _, ref := range h.Delta.Refs {
		if used[ref.Index] {
			return Inventory{}, errors.New("duplicate traffic reference")
		}
		used[ref.Index] = true
		var sample traffic.Sample
		if ref.Index >= 0 {
			if ref.Index >= len(base) || ref.At == nil || ref.At.IsZero() {
				return Inventory{}, errors.New("invalid traffic reference")
			}
			sample = base[ref.Index]
			sample.ObservedAt = *ref.At
		} else {
			// Bound the index before negating it to avoid integer overflow.
			if ref.Index < -len(h.NodeTraffic) || ref.At != nil {
				return Inventory{}, errors.New("invalid changed reference")
			}
			sample = h.NodeTraffic[-ref.Index-1]
			changed++
		}
		result.NodeTraffic = append(result.NodeTraffic, sample)
	}
	if changed != len(h.NodeTraffic) {
		return Inventory{}, errors.New("unreferenced traffic sample")
	}
	return result, nil
}
