package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lineops-agent/internal/agentconfig"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const DefaultFRPVersion = "0.61.1"

var frpHostPattern = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$`)
var frpProxyNamePattern = regexp.MustCompile(`^[A-Za-z0-9_\-\.\p{Han}]{1,64}$`)

type FRPProxy struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
	RemotePort int    `json:"remote_port"`
	NodeID     string `json:"node_id,omitempty"`
}

func (p FRPProxy) Normalized() FRPProxy {
	p.Name = strings.TrimSpace(p.Name)
	p.Protocol = strings.ToLower(strings.TrimSpace(p.Protocol))
	if p.Protocol == "" {
		p.Protocol = "tcp"
	}
	p.LocalIP = strings.TrimSpace(p.LocalIP)
	if p.LocalIP == "" {
		p.LocalIP = "127.0.0.1"
	}
	p.NodeID = strings.TrimSpace(p.NodeID)
	return p
}

func (p FRPProxy) Valid() bool {
	p = p.Normalized()
	if !frpProxyNamePattern.MatchString(p.Name) {
		return false
	}
	if p.Protocol != "tcp" && p.Protocol != "udp" && p.Protocol != "tcp+udp" {
		return false
	}
	if !validFRPHost(p.LocalIP) {
		return false
	}
	if p.LocalPort < 1 || p.LocalPort > 65535 || p.RemotePort < 1 || p.RemotePort > 65535 {
		return false
	}
	if p.NodeID != "" && !uuidPattern.MatchString(p.NodeID) {
		return false
	}
	return true
}

func validFRPHost(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 253 {
		return false
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return !addr.IsUnspecified() && !addr.IsMulticast()
	}
	return frpHostPattern.MatchString(s)
}

type FRPRequest struct {
	TaskID           string     `json:"task_id"`
	Kind             string     `json:"kind"`
	Fencing          uint64     `json:"fencing"`
	ServerEnabled    bool       `json:"server_enabled"`
	ServerBindPort   int        `json:"server_bind_port,omitempty"`
	ServerToken      string     `json:"server_token,omitempty"`
	ClientEnabled    bool       `json:"client_enabled"`
	ClientServerAddr string     `json:"client_server_addr,omitempty"`
	ClientServerPort int        `json:"client_server_port,omitempty"`
	ClientToken      string     `json:"client_token,omitempty"`
	ClientProxies    []FRPProxy `json:"client_proxies,omitempty"`
}

func (r FRPRequest) Valid() bool {
	if !uuidPattern.MatchString(r.TaskID) || r.Fencing < 1 || r.Fencing > 1_000_000_000_000 {
		return false
	}
	if r.Kind != "configure_frp" && r.Kind != "restart_frp" && r.Kind != "uninstall_frp" {
		return false
	}
	if r.Kind == "configure_frp" {
		if r.ServerEnabled {
			if r.ServerBindPort < 1 || r.ServerBindPort > 65535 {
				return false
			}
			if len(strings.TrimSpace(r.ServerToken)) < 8 || len(r.ServerToken) > 128 || strings.ContainsAny(r.ServerToken, "\r\n") {
				return false
			}
		}
		if r.ClientEnabled {
			if !validFRPHost(r.ClientServerAddr) || r.ClientServerPort < 1 || r.ClientServerPort > 65535 {
				return false
			}
			if len(strings.TrimSpace(r.ClientToken)) < 8 || len(r.ClientToken) > 128 || strings.ContainsAny(r.ClientToken, "\r\n") {
				return false
			}
			if len(r.ClientProxies) > 100 {
				return false
			}
			seenName := map[string]bool{}
			seenPort := map[string]bool{}
			for _, p := range r.ClientProxies {
				p = p.Normalized()
				if !p.Valid() || seenName[p.Name] {
					return false
				}
				seenName[p.Name] = true
				protos := []string{p.Protocol}
				if p.Protocol == "tcp+udp" {
					protos = []string{"tcp", "udp"}
				}
				for _, proto := range protos {
					key := fmt.Sprintf("%s:%d", proto, p.RemotePort)
					if seenPort[key] {
						return false
					}
					seenPort[key] = true
				}
			}
		}
	}
	return true
}

type FRPStatus struct {
	Installed        bool   `json:"installed"`
	Version          string `json:"version,omitempty"`
	ServerEnabled    bool   `json:"server_enabled"`
	ServerState      string `json:"server_state"`
	ServerBindPort   int    `json:"server_bind_port,omitempty"`
	ClientEnabled    bool   `json:"client_enabled"`
	ClientState      string `json:"client_state"`
	ClientServerAddr string `json:"client_server_addr,omitempty"`
	ClientServerPort int    `json:"client_server_port,omitempty"`
	ProxyCount       int    `json:"proxy_count,omitempty"`
}

func (s FRPStatus) Valid() bool {
	validState := func(st string) bool {
		return st == "running" || st == "stopped" || st == "failed" || st == "not_installed" || st == "unknown"
	}
	if len(s.Version) > 64 || !validState(s.ServerState) || !validState(s.ClientState) {
		return false
	}
	if s.ServerBindPort < 0 || s.ServerBindPort > 65535 || s.ClientServerPort < 0 || s.ClientServerPort > 65535 {
		return false
	}
	if len(s.ClientServerAddr) > 253 || s.ProxyCount < 0 || s.ProxyCount > 200 {
		return false
	}
	return true
}

type FRPResult struct {
	TaskID     string    `json:"task_id"`
	Kind       string    `json:"kind"`
	Fencing    uint64    `json:"fencing"`
	State      string    `json:"state"`
	Status     FRPStatus `json:"status"`
	ErrorCode  string    `json:"error_code,omitempty"`
	FinishedAt time.Time `json:"finished_at"`
}

func (r FRPResult) Valid() bool {
	if !uuidPattern.MatchString(r.TaskID) || r.Fencing < 1 || r.Fencing > 1_000_000_000_000 || r.FinishedAt.IsZero() {
		return false
	}
	if r.Kind != "configure_frp" && r.Kind != "restart_frp" && r.Kind != "uninstall_frp" {
		return false
	}
	if r.State != "succeeded" && r.State != "failed_manual" && r.State != "unknown" {
		return false
	}
	if len(r.ErrorCode) > 100 || !r.Status.Valid() {
		return false
	}
	return true
}

type frpLocalState struct {
	Version          string `json:"version"`
	ServerEnabled    bool   `json:"server_enabled"`
	ServerBindPort   int    `json:"server_bind_port,omitempty"`
	ClientEnabled    bool   `json:"client_enabled"`
	ClientServerAddr string `json:"client_server_addr,omitempty"`
	ClientServerPort int    `json:"client_server_port,omitempty"`
	ProxyCount       int    `json:"proxy_count,omitempty"`
	LastTaskID       string `json:"last_task_id,omitempty"`
	LastFencing      uint64 `json:"last_fencing,omitempty"`
}

func RenderFRPServerTOML(bindPort int, token string) string {
	var b strings.Builder
	b.WriteString("# Managed by LineOps Agent — DO NOT EDIT MANUALLY\n")
	b.WriteString("bindAddr = \"0.0.0.0\"\n")
	fmt.Fprintf(&b, "bindPort = %d\n", bindPort)
	b.WriteString("auth.method = \"token\"\n")
	fmt.Fprintf(&b, "auth.token = %s\n", strconv.Quote(strings.TrimSpace(token)))
	return b.String()
}

func RenderFRPClientTOML(serverAddr string, serverPort int, token string, proxies []FRPProxy) string {
	var b strings.Builder
	b.WriteString("# Managed by LineOps Agent — DO NOT EDIT MANUALLY\n")
	fmt.Fprintf(&b, "serverAddr = %s\n", strconv.Quote(strings.TrimSpace(serverAddr)))
	fmt.Fprintf(&b, "serverPort = %d\n", serverPort)
	b.WriteString("auth.method = \"token\"\n")
	fmt.Fprintf(&b, "auth.token = %s\n", strconv.Quote(strings.TrimSpace(token)))
	b.WriteString("loginFailExit = false\n")
	for _, p := range proxies {
		p = p.Normalized()
		if p.Protocol == "tcp+udp" {
			for _, proto := range []string{"tcp", "udp"} {
				b.WriteString("\n[[proxies]]\n")
				fmt.Fprintf(&b, "name = %s\n", strconv.Quote(p.Name+"-"+proto))
				fmt.Fprintf(&b, "type = %s\n", strconv.Quote(proto))
				fmt.Fprintf(&b, "localIP = %s\n", strconv.Quote(p.LocalIP))
				fmt.Fprintf(&b, "localPort = %d\n", p.LocalPort)
				fmt.Fprintf(&b, "remotePort = %d\n", p.RemotePort)
			}
		} else {
			b.WriteString("\n[[proxies]]\n")
			fmt.Fprintf(&b, "name = %s\n", strconv.Quote(p.Name))
			fmt.Fprintf(&b, "type = %s\n", strconv.Quote(p.Protocol))
			fmt.Fprintf(&b, "localIP = %s\n", strconv.Quote(p.LocalIP))
			fmt.Fprintf(&b, "localPort = %d\n", p.LocalPort)
			fmt.Fprintf(&b, "remotePort = %d\n", p.RemotePort)
		}
	}
	return b.String()
}

func EnsureFRPBinaries(ctx context.Context, frpDir string, needServer, needClient bool) (string, error) {
	if err := os.MkdirAll(frpDir, 0755); err != nil {
		return "", err
	}
	frpsPath := filepath.Join(frpDir, "frps")
	frpcPath := filepath.Join(frpDir, "frpc")
	hasServer := !needServer || isExecutableFile(frpsPath)
	hasClient := !needClient || isExecutableFile(frpcPath)
	if !hasServer {
		for _, candidate := range []string{"/usr/local/bin/frps", "/opt/homebrew/bin/frps", "/usr/bin/frps"} {
			if isExecutableFile(candidate) {
				if copyBinaryFile(candidate, frpsPath) == nil {
					hasServer = true
					break
				}
			}
		}
	}
	if !hasClient {
		for _, candidate := range []string{"/usr/local/bin/frpc", "/opt/homebrew/bin/frpc", "/usr/bin/frpc"} {
			if isExecutableFile(candidate) {
				if copyBinaryFile(candidate, frpcPath) == nil {
					hasClient = true
					break
				}
			}
		}
	}
	if !hasServer || !hasClient {
		if err := downloadFRPBinaries(ctx, frpDir, !hasServer, !hasClient); err != nil {
			return "", err
		}
	}
	ver := detectFRPVersion(frpsPath, frpcPath)
	if ver == "" {
		ver = DefaultFRPVersion
	}
	return ver, nil
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Size() > 1024
}

func copyBinaryFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeAtomicFile(dst, data, 0755)
}

func writeAtomicFile(dst string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-frp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, dst)
}

func downloadFRPBinaries(ctx context.Context, frpDir string, wantServer, wantClient bool) error {
	osName := runtime.GOOS
	arch := runtime.GOARCH
	if (osName != "linux" && osName != "darwin") || (arch != "amd64" && arch != "arm64") {
		return errors.New("frp_unsupported_platform")
	}
	client := &http.Client{Timeout: 3 * time.Minute}
	releaseBase := strings.TrimRight(os.Getenv("LINEOPS_AGENT_RELEASE_URL"), "/")
	if releaseBase == "" {
		releaseBase = "https://github.com/yo-brian/lineops-agent/releases/latest/download"
	}
	if wantServer {
		url := fmt.Sprintf("%s/lineops-frps-%s-%s", releaseBase, osName, arch)
		if data, err := fetchBoundedURL(ctx, client, url, 64<<20); err == nil && len(data) > 1024 {
			if writeAtomicFile(filepath.Join(frpDir, "frps"), data, 0755) == nil {
				wantServer = false
			}
		}
	}
	if wantClient {
		url := fmt.Sprintf("%s/lineops-frpc-%s-%s", releaseBase, osName, arch)
		if data, err := fetchBoundedURL(ctx, client, url, 64<<20); err == nil && len(data) > 1024 {
			if writeAtomicFile(filepath.Join(frpDir, "frpc"), data, 0755) == nil {
				wantClient = false
			}
		}
	}
	if !wantServer && !wantClient {
		return nil
	}
	tarURL := strings.TrimSpace(os.Getenv("LINEOPS_FRP_TARBALL_URL"))
	if tarURL == "" {
		tarURL = fmt.Sprintf("https://github.com/fatedier/frp/releases/download/v%s/frp_%s_%s_%s.tar.gz", DefaultFRPVersion, DefaultFRPVersion, osName, arch)
	}
	tarData, err := fetchBoundedURL(ctx, client, tarURL, 64<<20)
	if err != nil {
		return errors.New("frp_download_failed")
	}
	gz, err := gzip.NewReader(bytes.NewReader(tarData))
	if err != nil {
		return errors.New("frp_archive_invalid")
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	gotServer, gotClient := !wantServer, !wantClient
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("frp_archive_corrupted")
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := filepath.Base(hdr.Name)
		if base != "frps" && base != "frpc" {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, (64<<20)+1))
		if err != nil || len(data) > 64<<20 || len(data) < 1024 {
			return errors.New("frp_binary_invalid")
		}
		if err := writeAtomicFile(filepath.Join(frpDir, base), data, 0755); err != nil {
			return err
		}
		if base == "frps" {
			gotServer = true
		}
		if base == "frpc" {
			gotClient = true
		}
	}
	if !gotServer || !gotClient {
		return errors.New("frp_binary_missing_in_archive")
	}
	return nil
}

func fetchBoundedURL(ctx context.Context, client *http.Client, url string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil || int64(len(data)) > maxBytes {
		return nil, errors.New("response exceeded limit")
	}
	return data, nil
}

func detectFRPVersion(paths ...string) string {
	for _, p := range paths {
		if !isExecutableFile(p) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		out, err := exec.CommandContext(ctx, p, "-v").CombinedOutput()
		cancel()
		if err == nil {
			v := strings.TrimSpace(string(out))
			if v != "" && len(v) <= 40 && !strings.ContainsAny(v, "\r\n") {
				return v
			}
		}
	}
	return ""
}

func ObserveFRP(paths agentconfig.Paths) FRPStatus {
	frpDir := paths.FRPDir()
	frpsBin := filepath.Join(frpDir, "frps")
	frpcBin := filepath.Join(frpDir, "frpc")
	status := FRPStatus{
		Installed:   isExecutableFile(frpsBin) || isExecutableFile(frpcBin),
		ServerState: observeFRPServiceState("frps", frpDir),
		ClientState: observeFRPServiceState("frpc", frpDir),
	}
	var local frpLocalState
	if data, err := os.ReadFile(filepath.Join(frpDir, "state.json")); err == nil {
		if json.Unmarshal(data, &local) == nil {
			status.Version = local.Version
			status.ServerEnabled = local.ServerEnabled
			status.ServerBindPort = local.ServerBindPort
			status.ClientEnabled = local.ClientEnabled
			status.ClientServerAddr = local.ClientServerAddr
			status.ClientServerPort = local.ClientServerPort
			status.ProxyCount = local.ProxyCount
		}
	}
	if status.Installed && status.Version == "" {
		status.Version = detectFRPVersion(frpsBin, frpcBin)
		if status.Version == "" {
			status.Version = DefaultFRPVersion
		}
	}
	return status
}

func ApplyFRP(ctx context.Context, paths agentconfig.Paths, req FRPRequest) FRPResult {
	res := FRPResult{
		TaskID:     req.TaskID,
		Kind:       req.Kind,
		Fencing:    req.Fencing,
		State:      "failed_manual",
		FinishedAt: time.Now().UTC(),
	}
	if !req.Valid() {
		res.ErrorCode = "invalid_frp_request"
		res.Status = ObserveFRP(paths)
		return res
	}
	frpDir := paths.FRPDir()
	var local frpLocalState
	if data, err := os.ReadFile(filepath.Join(frpDir, "state.json")); err == nil {
		_ = json.Unmarshal(data, &local)
		if local.LastFencing > req.Fencing {
			res.ErrorCode = "stale_or_conflicting_task"
			res.Status = ObserveFRP(paths)
			return res
		}
	}

	switch req.Kind {
	case "uninstall_frp":
		_ = stopAndRemoveFRPService(ctx, "frps")
		_ = stopAndRemoveFRPService(ctx, "frpc")
		_ = os.Remove(filepath.Join(frpDir, "frps.toml"))
		_ = os.Remove(filepath.Join(frpDir, "frpc.toml"))
		_ = os.Remove(filepath.Join(frpDir, "frps"))
		_ = os.Remove(filepath.Join(frpDir, "frpc"))
		_ = os.Remove(filepath.Join(frpDir, "state.json"))
		res.State = "succeeded"
		res.Status = ObserveFRP(paths)
		res.FinishedAt = time.Now().UTC()
		return res

	case "restart_frp":
		if local.ServerEnabled {
			if err := restartFRPService(ctx, "frps", frpDir); err != nil {
				res.ErrorCode = "frps_restart_failed"
				res.Status = ObserveFRP(paths)
				res.FinishedAt = time.Now().UTC()
				return res
			}
		}
		if local.ClientEnabled {
			if err := restartFRPService(ctx, "frpc", frpDir); err != nil {
				res.ErrorCode = "frpc_restart_failed"
				res.Status = ObserveFRP(paths)
				res.FinishedAt = time.Now().UTC()
				return res
			}
		}
		local.LastTaskID = req.TaskID
		local.LastFencing = req.Fencing
		if data, err := json.Marshal(local); err == nil {
			_ = writeAtomicFile(filepath.Join(frpDir, "state.json"), data, 0600)
		}
		res.State = "succeeded"
		res.Status = ObserveFRP(paths)
		res.FinishedAt = time.Now().UTC()
		return res

	case "configure_frp":
		if !req.ServerEnabled && !req.ClientEnabled {
			_ = stopAndRemoveFRPService(ctx, "frps")
			_ = stopAndRemoveFRPService(ctx, "frpc")
			_ = os.Remove(filepath.Join(frpDir, "frps.toml"))
			_ = os.Remove(filepath.Join(frpDir, "frpc.toml"))
			local = frpLocalState{
				Version:     local.Version,
				LastTaskID:  req.TaskID,
				LastFencing: req.Fencing,
			}
			if data, err := json.Marshal(local); err == nil {
				_ = writeAtomicFile(filepath.Join(frpDir, "state.json"), data, 0600)
			}
			res.State = "succeeded"
			res.Status = ObserveFRP(paths)
			res.FinishedAt = time.Now().UTC()
			return res
		}
		ver, err := EnsureFRPBinaries(ctx, frpDir, req.ServerEnabled, req.ClientEnabled)
		if err != nil {
			res.ErrorCode = err.Error()
			res.Status = ObserveFRP(paths)
			res.FinishedAt = time.Now().UTC()
			return res
		}
		if req.ServerEnabled {
			cfg := RenderFRPServerTOML(req.ServerBindPort, req.ServerToken)
			if err := writeAtomicFile(filepath.Join(frpDir, "frps.toml"), []byte(cfg), 0600); err != nil {
				res.ErrorCode = "frps_config_write_failed"
				res.Status = ObserveFRP(paths)
				res.FinishedAt = time.Now().UTC()
				return res
			}
			if err := installAndStartFRPService(ctx, "frps", frpDir); err != nil {
				res.ErrorCode = "frps_service_start_failed"
				res.Status = ObserveFRP(paths)
				res.FinishedAt = time.Now().UTC()
				return res
			}
		} else {
			_ = stopAndRemoveFRPService(ctx, "frps")
			_ = os.Remove(filepath.Join(frpDir, "frps.toml"))
		}

		if req.ClientEnabled {
			cfg := RenderFRPClientTOML(req.ClientServerAddr, req.ClientServerPort, req.ClientToken, req.ClientProxies)
			if err := writeAtomicFile(filepath.Join(frpDir, "frpc.toml"), []byte(cfg), 0600); err != nil {
				res.ErrorCode = "frpc_config_write_failed"
				res.Status = ObserveFRP(paths)
				res.FinishedAt = time.Now().UTC()
				return res
			}
			if err := installAndStartFRPService(ctx, "frpc", frpDir); err != nil {
				res.ErrorCode = "frpc_service_start_failed"
				res.Status = ObserveFRP(paths)
				res.FinishedAt = time.Now().UTC()
				return res
			}
		} else {
			_ = stopAndRemoveFRPService(ctx, "frpc")
			_ = os.Remove(filepath.Join(frpDir, "frpc.toml"))
		}

		local = frpLocalState{
			Version:          ver,
			ServerEnabled:    req.ServerEnabled,
			ServerBindPort:   req.ServerBindPort,
			ClientEnabled:    req.ClientEnabled,
			ClientServerAddr: req.ClientServerAddr,
			ClientServerPort: req.ClientServerPort,
			ProxyCount:       len(req.ClientProxies),
			LastTaskID:       req.TaskID,
			LastFencing:      req.Fencing,
		}
		if data, err := json.Marshal(local); err == nil {
			_ = writeAtomicFile(filepath.Join(frpDir, "state.json"), data, 0600)
		}
		res.State = "succeeded"
		res.Status = ObserveFRP(paths)
		res.FinishedAt = time.Now().UTC()
		return res
	}
	res.ErrorCode = "unsupported_frp_operation"
	res.Status = ObserveFRP(paths)
	return res
}

func observeFRPServiceState(role, frpDir string) string {
	binPath := filepath.Join(frpDir, role)
	cfgPath := filepath.Join(frpDir, role+".toml")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if !isExecutableFile(binPath) {
			return "not_installed"
		}
		return "stopped"
	}
	if runtime.GOOS == "darwin" {
		plist := fmt.Sprintf("/Library/LaunchDaemons/com.lineops.%s.plist", role)
		if _, err := os.Stat(plist); os.IsNotExist(err) {
			return "stopped"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		out, err := exec.CommandContext(ctx, "/bin/launchctl", "print", fmt.Sprintf("system/com.lineops.%s", role)).CombinedOutput()
		cancel()
		if err != nil {
			return "stopped"
		}
		text := string(out)
		if strings.Contains(text, "state = running") {
			return "running"
		}
		if strings.Contains(text, "last exit code = 0") || strings.Contains(text, "last exit code = (never exited)") {
			return "stopped"
		}
		return "failed"
	}
	if runtime.GOOS == "linux" {
		unit := fmt.Sprintf("lineops-%s.service", role)
		unitFile := filepath.Join("/etc/systemd/system", unit)
		if _, err := os.Stat(unitFile); os.IsNotExist(err) {
			return "stopped"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		out, _ := exec.CommandContext(ctx, "systemctl", "is-active", unit).CombinedOutput()
		cancel()
		switch strings.TrimSpace(string(out)) {
		case "active", "activating", "reloading":
			return "running"
		case "failed":
			return "failed"
		default:
			return "stopped"
		}
	}
	return "stopped"
}

func installAndStartFRPService(ctx context.Context, role, frpDir string) error {
	binPath := filepath.Join(frpDir, role)
	cfgPath := filepath.Join(frpDir, role+".toml")
	if runtime.GOOS == "darwin" {
		label := fmt.Sprintf("com.lineops.%s", role)
		plistPath := fmt.Sprintf("/Library/LaunchDaemons/%s.plist", label)
		logPath := fmt.Sprintf("/var/log/lineops-%s.log", role)
		plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>-c</string>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, label, binPath, cfgPath, logPath, logPath)
		if err := writeAtomicFile(plistPath, []byte(plist), 0644); err != nil {
			return err
		}
		_ = os.Chown(plistPath, 0, 0)
		_ = exec.CommandContext(ctx, "/bin/launchctl", "bootout", "system", plistPath).Run()
		_ = exec.CommandContext(ctx, "/bin/launchctl", "enable", "system/"+label).Run()
		if err := exec.CommandContext(ctx, "/bin/launchctl", "bootstrap", "system", plistPath).Run(); err != nil {
			if err2 := exec.CommandContext(ctx, "/bin/launchctl", "load", "-w", plistPath).Run(); err2 != nil {
				return err
			}
		}
		_ = exec.CommandContext(ctx, "/bin/launchctl", "kickstart", "-k", "system/"+label).Run()
		time.Sleep(300 * time.Millisecond)
		if st := observeFRPServiceState(role, frpDir); st != "running" {
			return errors.New("frp_service_not_running")
		}
		return nil
	}
	if runtime.GOOS == "linux" {
		unit := fmt.Sprintf("lineops-%s.service", role)
		unitPath := filepath.Join("/etc/systemd/system", unit)
		content := fmt.Sprintf(`[Unit]
Description=LineOps Managed FRP (%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s -c %s
Restart=always
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, role, binPath, cfgPath)
		if err := writeAtomicFile(unitPath, []byte(content), 0644); err != nil {
			return err
		}
		_ = exec.CommandContext(ctx, "systemctl", "daemon-reload").Run()
		_ = exec.CommandContext(ctx, "systemctl", "enable", unit).Run()
		if err := exec.CommandContext(ctx, "systemctl", "restart", unit).Run(); err != nil {
			return err
		}
		time.Sleep(300 * time.Millisecond)
		if st := observeFRPServiceState(role, frpDir); st != "running" {
			return errors.New("frp_service_not_running")
		}
		return nil
	}
	return nil
}

func restartFRPService(ctx context.Context, role, frpDir string) error {
	return installAndStartFRPService(ctx, role, frpDir)
}

func stopAndRemoveFRPService(ctx context.Context, role string) error {
	if runtime.GOOS == "darwin" {
		label := fmt.Sprintf("com.lineops.%s", role)
		plistPath := fmt.Sprintf("/Library/LaunchDaemons/%s.plist", label)
		_ = exec.CommandContext(ctx, "/bin/launchctl", "bootout", "system", plistPath).Run()
		_ = exec.CommandContext(ctx, "/bin/launchctl", "unload", plistPath).Run()
		_ = os.Remove(plistPath)
		return nil
	}
	if runtime.GOOS == "linux" {
		unit := fmt.Sprintf("lineops-%s.service", role)
		unitPath := filepath.Join("/etc/systemd/system", unit)
		_ = exec.CommandContext(ctx, "systemctl", "disable", "--now", unit).Run()
		_ = os.Remove(unitPath)
		_ = exec.CommandContext(ctx, "systemctl", "daemon-reload").Run()
		return nil
	}
	return nil
}
