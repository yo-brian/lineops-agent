//go:build linux

package agent

import (
	"lineops-agent/internal/traffic"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Count hardware-backed NICs (including virtio NICs), excluding loopback,
// bridges, veth and tunnels so traffic is not counted again on virtual layers.
func hostTraffic() []traffic.Sample {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	var samples []traffic.Sample
	now := time.Now().UTC()
	for _, entry := range entries {
		if len(samples) >= 64 {
			break
		}
		dir := filepath.Join("/sys/class/net", entry.Name())
		if _, err = os.Stat(filepath.Join(dir, "device")); err != nil {
			continue
		}
		read := func(name string) (uint64, error) {
			b, e := os.ReadFile(filepath.Join(dir, name))
			if e != nil {
				return 0, e
			}
			return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		}
		up, e1 := read("statistics/tx_bytes")
		down, e2 := read("statistics/rx_bytes")
		index, e3 := read("ifindex")
		if e1 != nil || e2 != nil || e3 != nil {
			continue
		}
		samples = append(samples, traffic.Sample{Source: strings.TrimSpace(string(boot)) + ":" + strconv.FormatUint(index, 10), Upload: up, Download: down, ObservedAt: now})
	}
	return samples
}
