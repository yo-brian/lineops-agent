//go:build darwin

package agent

import (
	"context"
	"encoding/json"
	"lineops-agent/internal/agentproto"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var darwinBootSec = regexp.MustCompile(`sec\s*=\s*([0-9]+)`)

func Inventory() agentproto.Inventory {
	i := agentproto.Inventory{
		AgentVersion:       agentproto.Version,
		OS:                 "macOS",
		Architecture:       runtime.GOARCH,
		ServiceName:        "com.lineops.agent",
		ServiceState:       "active",
		RunningMode:        "launchd",
		ConfigurationState: "read_only",
		ProtocolState:      "not_verified",
	}
	i.Hostname, _ = os.Hostname()
	i.CPUCount = runtime.NumCPU()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if out, err := exec.CommandContext(ctx, "/usr/bin/sw_vers", "-productVersion").Output(); err == nil {
		if ver := strings.TrimSpace(string(out)); ver != "" && len(ver) < 60 {
			i.OS = "macOS " + ver
		}
	}
	if out, err := exec.CommandContext(ctx, "/usr/sbin/sysctl", "-n", "kern.boottime").Output(); err == nil {
		if m := darwinBootSec.FindStringSubmatch(string(out)); len(m) == 2 {
			if bootSec, err := strconv.ParseInt(m[1], 10, 64); err == nil {
				now := time.Now().Unix()
				if now > bootSec {
					i.UptimeSeconds = uint64(now - bootSec)
				}
			}
		}
	}
	if out, err := exec.CommandContext(ctx, "/usr/sbin/sysctl", "-n", "vm.loadavg").Output(); err == nil {
		load := strings.TrimSpace(strings.Trim(strings.TrimSpace(string(out)), "{}"))
		fields := strings.Fields(load)
		if len(fields) >= 3 {
			i.LoadAverage = strings.Join(fields[:3], " ")
		}
	}
	if out, err := exec.CommandContext(ctx, "/usr/sbin/sysctl", "-n", "hw.memsize").Output(); err == nil {
		if bytesTotal, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64); err == nil {
			i.MemoryTotalKB = bytesTotal / 1024
			i.MemoryAvailableKB = i.MemoryTotalKB / 2
		}
	}
	if out, err := exec.CommandContext(ctx, "/usr/bin/vm_stat").Output(); err == nil {
		var freePages, inactivePages, speculativePages uint64
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "Pages free:") {
				freePages = parseVMStatPages(line)
			} else if strings.HasPrefix(line, "Pages inactive:") {
				inactivePages = parseVMStatPages(line)
			} else if strings.HasPrefix(line, "Pages speculative:") {
				speculativePages = parseVMStatPages(line)
			}
		}
		availKB := (freePages + inactivePages + speculativePages) * (uint64(os.Getpagesize()) / 1024)
		if availKB > 0 && (i.MemoryTotalKB == 0 || availKB <= i.MemoryTotalKB) {
			i.MemoryAvailableKB = availKB
		}
	}
	var stat syscall.Statfs_t
	if syscall.Statfs("/", &stat) == nil {
		i.DiskTotalBytes = stat.Blocks * uint64(stat.Bsize)
		i.DiskAvailableBytes = stat.Bavail * uint64(stat.Bsize)
	}
	for _, path := range []string{"/etc/lineops/bin/lineops-singbox", "/etc/lineops/bin/sing-box", "/opt/homebrew/bin/sing-box", "/usr/local/bin/sing-box"} {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			i.BinaryPath = path
			vCtx, vCancel := context.WithTimeout(context.Background(), 3*time.Second)
			data, err := exec.CommandContext(vCtx, path, "version").Output()
			vCancel()
			if err == nil {
				line := strings.SplitN(string(data), "\n", 2)[0]
				if len(line) < 200 {
					i.BinaryVersion = strings.TrimSpace(line)
				}
			}
			break
		}
	}
	return i
}

func parseVMStatPages(line string) uint64 {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return 0
	}
	v := strings.TrimSuffix(strings.TrimSpace(parts[1]), ".")
	n, _ := strconv.ParseUint(v, 10, 64)
	return n
}

func CollectAgentLogs() []string {
	return tailLogFile("/var/log/lineops-agent.log", 80)
}

func observeManagedServiceLogs(id string) []string {
	if len(id) != 36 || strings.ContainsAny(id, "/\\. \n") {
		return nil
	}
	return tailLogFile("/var/log/lineops-sing-box-"+id+".log", 60)
}

func tailLogFile(path string, maxLines int) []string {
	if maxLines <= 0 || maxLines > 100 {
		maxLines = 60
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}
	if len(data) > 64<<10 {
		data = data[len(data)-(64<<10):]
	}
	rawLines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(rawLines) > maxLines {
		rawLines = rawLines[len(rawLines)-maxLines:]
	}
	out := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if len(line) > 512 {
			line = line[:512]
		}
		out = append(out, line)
	}
	return out
}

func observeManagedService(id string) agentproto.ServiceObservation {
	result := agentproto.ServiceObservation{InstanceID: id, State: "unknown"}
	if len(id) != 36 || strings.ContainsAny(id, "/\\. \n") {
		return result
	}
	plist := "/Library/LaunchDaemons/com.lineops.sing-box." + id + ".plist"
	if _, err := os.Stat(plist); os.IsNotExist(err) {
		result.State = "not_installed"
		return result
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/launchctl", "print", "system/com.lineops.sing-box."+id).Output()
	if err != nil {
		result.State = "stopped"
	} else if strings.Contains(string(out), "state = running") {
		result.State = "running"
	} else {
		result.State = "stopped"
	}
	for _, instRoot := range []string{"/var/lib/lineops/instances", "/etc/lineops/instances"} {
		if rtBytes, err := os.ReadFile(filepath.Join(instRoot, id, "runtime.json")); err == nil && len(rtBytes) < 16384 {
			var rt struct {
				BinaryVersion string `json:"binary_version"`
			}
			if json.Unmarshal(rtBytes, &rt) == nil && len(rt.BinaryVersion) <= 80 {
				result.Version = rt.BinaryVersion
				break
			}
		}
	}
	return result
}
