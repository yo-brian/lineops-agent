//go:build darwin

package agent

import (
	"context"
	"lineops-agent/internal/traffic"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func hostTraffic() []traffic.Sample {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	bootOut, err := exec.CommandContext(ctx, "/usr/sbin/sysctl", "-n", "kern.bootsessionuuid").Output()
	boot := strings.TrimSpace(string(bootOut))
	if err != nil || boot == "" {
		boot = "darwin"
	}
	out, err := exec.CommandContext(ctx, "/usr/sbin/netstat", "-ibn").Output()
	if err != nil {
		return nil
	}
	var samples []traffic.Sample
	seen := map[string]bool{}
	now := time.Now().UTC()
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		// netstat -ibn Link row: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
		if len(fields) < 10 || !strings.HasPrefix(fields[2], "<Link#") {
			continue
		}
		name := fields[0]
		if !strings.HasPrefix(name, "en") || seen[name] {
			continue
		}
		ibytes, e1 := strconv.ParseUint(fields[6], 10, 64)
		obytes, e2 := strconv.ParseUint(fields[9], 10, 64)
		if e1 != nil || e2 != nil || (ibytes == 0 && obytes == 0) {
			continue
		}
		seen[name] = true
		samples = append(samples, traffic.Sample{
			Source:     boot + ":" + name,
			Upload:     obytes,
			Download:   ibytes,
			ObservedAt: now,
		})
		if len(samples) >= 16 {
			break
		}
	}
	return samples
}
