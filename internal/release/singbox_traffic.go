package release

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lineop-agent/internal/traffic"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/protobuf/encoding/protowire"
)

// Each instance gets a loopback address. The listener also participates in the
// normal host port reservation checks; collisions fail before publication.
func trafficListener(id string, _ Model) Node {
	h := sha256.Sum256([]byte(id))
	port := uint16(19090) + uint16(h[3])*64 + uint16(h[4]%64)
	return Node{Listen: fmt.Sprintf("127.%d.%d.%d", h[0], h[1], h[2]), Port: port}
}

func addTrafficAPI(config []byte, id string, m Model) ([]byte, error) {
	if !uuidPattern.MatchString(id) {
		return nil, errors.New("invalid traffic instance")
	}
	var value map[string]any
	if err := json.Unmarshal(config, &value); err != nil {
		return nil, err
	}
	n := trafficListener(id, m)
	for _, node := range m.Nodes {
		if PortConflict(n, node) {
			return nil, errors.New("node port conflicts with local statistics listener")
		}
	}
	users := []string{}
	tags := make([]string, 0, len(m.Nodes))
	for _, node := range m.Nodes {
		tags = append(tags, "node-"+node.ID)
		for _, u := range node.Users {
			users = append(users, "credential-"+u.ID)
		}
	}
	sort.Strings(tags)
	value["experimental"] = map[string]any{"v2ray_api": map[string]any{
		"listen": net.JoinHostPort(n.Listen, strconv.Itoa(int(n.Port))),
		"stats":  map[string]any{"enabled": true, "inbounds": tags, "users": users},
	}}
	return json.MarshalIndent(value, "", "  ")
}

// QueryStats uses the upstream V2Ray StatsService protobuf wire format. It never
// resets counters. Keeping this small read-only client avoids importing a proxy
// core or exposing its management methods to the unprivileged Agent.
func querySingboxTraffic(ctx context.Context, endpoint string) (map[string]uint64, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return nil, errors.New("invalid traffic endpoint")
	}
	transport := &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", endpoint)
	}}
	defer transport.CloseIdleConnections()
	payload := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "")
	frame := make([]byte, 5, 5+len(payload))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	frame = append(frame, payload...)
	req, err := http.NewRequestWithContext(ctx, "POST", "http://"+endpoint+"/v2ray.core.app.stats.command.StatsService/QueryStats", bytes.NewReader(frame))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	resp, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return nil, errors.New("singbox_stats_unavailable")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	status := resp.Trailer.Get("Grpc-Status")
	if status == "" {
		status = resp.Header.Get("Grpc-Status")
	}
	if err != nil || resp.StatusCode != 200 || status != "0" || len(raw) < 5 || len(raw) > 4<<20 || raw[0] != 0 || int(binary.BigEndian.Uint32(raw[1:5])) != len(raw)-5 {
		return nil, errors.New("singbox_stats_invalid")
	}
	return decodeSingboxStats(raw[5:])
}

func decodeSingboxStats(raw []byte) (map[string]uint64, error) {
	stats := map[string]uint64{}
	err := wireFields(raw, func(n protowire.Number, typ protowire.Type, b []byte) error {
		if n != 1 {
			return nil
		}
		if typ != protowire.BytesType {
			return errors.New("invalid stat")
		}
		value, _ := protowire.ConsumeBytes(b)
		var name string
		var count uint64
		err := wireFields(value, func(n protowire.Number, typ protowire.Type, b []byte) error {
			switch n {
			case 1:
				if typ != protowire.BytesType {
					return errors.New("invalid stat name")
				}
				name, _ = protowire.ConsumeString(b)
			case 2:
				if typ != protowire.VarintType {
					return errors.New("invalid stat value")
				}
				count, _ = protowire.ConsumeVarint(b)
			}
			return nil
		})
		if err != nil || name == "" || len(name) > 160 || count >= 1<<60 || len(stats) >= 8192 {
			return errors.New("invalid stat")
		}
		if _, exists := stats[name]; exists {
			return errors.New("duplicate stat")
		}
		stats[name] = count
		return nil
	})
	return stats, err
}

func wireFields(raw []byte, visit func(protowire.Number, protowire.Type, []byte) error) error {
	for len(raw) > 0 {
		n, typ, size := protowire.ConsumeTag(raw)
		if size < 0 {
			return errors.New("invalid protobuf tag")
		}
		raw = raw[size:]
		size = protowire.ConsumeFieldValue(n, typ, raw)
		if size < 0 {
			return errors.New("invalid protobuf value")
		}
		if err := visit(n, typ, raw[:size]); err != nil {
			return err
		}
		raw = raw[size:]
	}
	return nil
}

func singboxSamples(m Model, source string, counters map[string]uint64, at time.Time) []traffic.Sample {
	result := make([]traffic.Sample, 0, len(m.Nodes))
	for _, n := range m.Nodes {
		prefix := "inbound>>>node-" + n.ID + ">>>traffic>>>"
		// sing-box creates counters lazily. A successful query with no entry is
		// a measured zero, not a collection failure.
		result = append(result, traffic.Sample{ResourceID: n.ID, Source: "singbox-v1:" + source, Upload: counters[prefix+"uplink"], Download: counters[prefix+"downlink"], ObservedAt: at})
	}
	for _, n := range m.Nodes {
		for _, u := range n.Users {
			prefix := "user>>>credential-" + u.ID + ">>>traffic>>>"
			result = append(result, traffic.Sample{ResourceID: u.ID, Source: "singbox-user-v1:" + source, Upload: counters[prefix+"uplink"], Download: counters[prefix+"downlink"], ObservedAt: at})
		}
	}
	return result
}

func TrafficErrorCode(err error) string {
	if err != nil {
		switch err.Error() {
		case "singbox_stats_upgrade_required", "singbox_stats_publish_required", "singbox_stats_service_inactive", "singbox_stats_unavailable", "singbox_stats_invalid":
			return err.Error()
		}
	}
	return "node_traffic_unavailable"
}

func validInvocation(value string) bool {
	if len(value) != 32 {
		return false
	}
	return strings.IndexFunc(value, func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') }) == -1
}
