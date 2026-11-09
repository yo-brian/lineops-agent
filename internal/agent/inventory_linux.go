//go:build linux

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"lineops-agent/internal/agentproto"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func Inventory() agentproto.Inventory {
	i := agentproto.Inventory{AgentVersion: agentproto.Version, Architecture: runtime.GOARCH, ServiceName: "sing-box.service", ServiceState: "unknown", ConfigurationState: "read_only", ProtocolState: "not_verified"}
	i.Hostname, _ = os.Hostname()
	i.CPUCount = runtime.NumCPU()
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			seconds, _ := strconv.ParseFloat(fields[0], 64)
			if seconds >= 0 {
				i.UptimeSeconds = uint64(seconds)
			}
		}
	}
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				i.OS = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
			}
		}
	}
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			i.LoadAverage = strings.Join(fields[:3], " ")
		}
	}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			n, _ := strconv.ParseUint(f[1], 10, 64)
			if f[0] == "MemTotal:" {
				i.MemoryTotalKB = n
			}
			if f[0] == "MemAvailable:" {
				i.MemoryAvailableKB = n
			}
		}
	}
	var stat syscall.Statfs_t
	if syscall.Statfs("/", &stat) == nil {
		i.DiskTotalBytes = stat.Blocks * uint64(stat.Bsize)
		i.DiskAvailableBytes = stat.Bavail * uint64(stat.Bsize)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Fixed program and fixed arguments only. Unknown installations remain read-only.
	if data, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "sing-box.service", "--property=LoadState,ActiveState,MainPID", "--no-pager").Output(); err == nil {
		values := string(data)
		i.RunningMode = "systemd"
		if strings.Contains(values, "LoadState=not-found") {
			i.ServiceState = "not_found"
		} else if strings.Contains(values, "ActiveState=active") {
			i.ServiceState = "active"
		} else if strings.Contains(values, "ActiveState=inactive") {
			i.ServiceState = "inactive"
		} else if strings.Contains(values, "ActiveState=failed") {
			i.ServiceState = "failed"
		} else {
			i.ServiceState = "unknown"
		}
		for _, line := range strings.Split(values, "\n") {
			if strings.HasPrefix(line, "MainPID=") {
				pid, e := strconv.Atoi(strings.TrimPrefix(line, "MainPID="))
				if e == nil && pid > 1 {
					observeConfig(pid, &i)
				}
			}
		}
	} else {
		i.ErrorCode = "systemd_observation_unavailable"
	}
	for _, path := range []string{"/usr/bin/sing-box", "/usr/local/bin/sing-box"} {
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
			i.BinaryPath = path
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			data, err := exec.CommandContext(ctx, path, "version").Output()
			cancel()
			if err == nil {
				line := strings.SplitN(string(data), "\n", 2)[0]
				if len(line) < 200 {
					i.BinaryVersion = line
				}
			}
			break
		}
	}
	return i
}

func CollectAgentLogs() []string {
	return collectJournalTail("lineops-agent.service", 80)
}

// collectJournalTail reads bounded systemd journal lines.
func collectJournalTailHelper() {
}

func collectJournalTail(unit string, maxLines int) []string {
	if maxLines <= 0 || maxLines > 100 {
		maxLines = 60
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	data, err := exec.CommandContext(ctx, "/usr/bin/journalctl", "-u", unit, "-n", strconv.Itoa(maxLines), "--no-pager", "--output=short-iso").Output()
	if err != nil || len(data) == 0 {
		return nil
	}
	rawLines := strings.Split(strings.TrimSpace(string(data)), "\n")
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
		if len(out) >= maxLines {
			break
		}
	}
	return out
}

func observeManagedServiceLogs(id string) []string {
	if len(id) != 36 || strings.ContainsAny(id, "/\\. \n") {
		return nil
	}
	return collectJournalTail("lineops-sing-box-"+id+".service", 60)
}

// Read only known sing-box configuration locations. Never expose raw argv,
// configuration contents, credentials or arbitrary files named by a service.
func observeConfig(pid int, i *agentproto.Inventory) {
	i.ConfigurationLoad = "unknown"
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(b) > 65536 {
		return
	}
	args := strings.Split(string(b), "\x00")
	if len(args) == 0 {
		return
	}
	config := ""
	count := 0
	for n := 1; n < len(args); n++ {
		a := args[n]
		if a == "-C" || a == "--config-directory" || strings.HasPrefix(a, "--config-directory=") {
			i.ConfigurationLoad = "directory_read_only"
			return
		}
		if a == "-c" || a == "--config" {
			if n+1 >= len(args) {
				return
			}
			n++
			config = args[n]
			count++
		} else if strings.HasPrefix(a, "--config=") {
			config = strings.TrimPrefix(a, "--config=")
			count++
		}
	}
	if count != 1 {
		i.ConfigurationLoad = "default_or_multiple_read_only"
		return
	}
	path := filepath.Clean(config)
	root := "/etc/sing-box/"
	if !filepath.IsAbs(path) || !strings.HasPrefix(path, root) || filepath.Ext(path) != ".json" {
		i.ConfigurationLoad = "unsupported_location_read_only"
		return
	}
	for p := path; p != "/"; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil || info.Mode()&os.ModeSymlink != 0 {
			i.ConfigurationLoad = "unsafe_or_unreadable_read_only"
			return
		}
	}
	i.ConfigurationPath = path
	i.ConfigurationLoad = "single_file_read_only"
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return
	}
	b, err = os.ReadFile(path)
	if err != nil {
		return
	}
	sum := sha256.Sum256(b)
	i.ConfigurationHash = hex.EncodeToString(sum[:])
}

func observeManagedService(id string) agentproto.ServiceObservation {
	result := agentproto.ServiceObservation{InstanceID: id, State: "unknown"}
	if len(id) != 36 || strings.ContainsAny(id, "/\\. \n") {
		return result
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	data, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "lineops-sing-box-"+id+".service", "--property=LoadState,ActiveState", "--no-pager").Output()
	if err != nil {
		return result
	}
	value := string(data)
	switch {
	case strings.Contains(value, "LoadState=not-found"):
		result.State = "not_installed"
	case strings.Contains(value, "ActiveState=active"):
		result.State = "running"
	case strings.Contains(value, "ActiveState=inactive"):
		result.State = "stopped"
	case strings.Contains(value, "ActiveState=failed"):
		result.State = "failed"
	}
	if rtBytes, err := os.ReadFile(filepath.Join("/etc/lineops/instances", id, "runtime.json")); err == nil && len(rtBytes) < 16384 {
		var rt struct {
			BinaryVersion string `json:"binary_version"`
		}
		if json.Unmarshal(rtBytes, &rt) == nil && len(rt.BinaryVersion) <= 80 {
			result.Version = rt.BinaryVersion
		}
	}
	return result
}
