//go:build darwin

package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func matchSupportedVersion(out []byte, targetVersion string) string {
	if targetVersion != "" && !SupportedSingboxVersion(targetVersion) {
		return ""
	}
	if !strings.Contains(string(out), "with_v2ray_api") || !outputHasVersion(out, DefaultSingboxVersion) {
		return ""
	}
	return DefaultSingboxVersion
}

func (e Engine) lifecycleBinary(ctx context.Context, targetVersion string) ([]byte, string, error) {
	if targetVersion != "" && !SupportedSingboxVersion(targetVersion) {
		return nil, "", errors.New("unsupported_singbox_version")
	}
	binDir := e.ManagedPaths().AgentBinDir
	candidates := []string{
		filepath.Join(binDir, "lineops-singbox"),
		filepath.Join(binDir, "sing-box"),
		"/opt/homebrew/bin/sing-box",
		"/usr/local/bin/sing-box",
		"/usr/bin/sing-box",
	}
	for _, candidate := range candidates {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		out, err := exec.CommandContext(ctx, resolved, "version").Output()
		if err != nil {
			continue
		}
		if matched := matchSupportedVersion(out, targetVersion); matched != "" {
			data, err := readBinary(resolved)
			if err == nil && len(data) > 0 {
				return data, matched, nil
			}
		}
	}
	if binDir != "" && safeDir(binDir, true) == nil {
		arch := runtime.GOARCH
		url := "https://github.com/yo-brian/lineops-agent/releases/latest/download/lineops-singbox-darwin-" + arch
		tmpFile := filepath.Join(binDir, ".lineops-singbox-download-"+DefaultSingboxVersion)
		defer os.Remove(tmpFile)
		_ = os.Remove(tmpFile)
		dlCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		err := exec.CommandContext(dlCtx, "curl", "--fail", "--silent", "--location", "--connect-timeout", "15", "--max-time", "180", "--retry", "2", url, "-o", tmpFile).Run()
		cancel()
		if err == nil {
			_ = os.Chown(tmpFile, 0, 0)
			_ = os.Chmod(tmpFile, 0755)
			if out, err := exec.CommandContext(ctx, tmpFile, "version").Output(); err == nil {
				if matched := matchSupportedVersion(out, targetVersion); matched != "" {
					if data, err := readBinary(tmpFile); err == nil {
						_ = writeFile(filepath.Join(binDir, "lineops-singbox"), data, 0755)
						return data, matched, nil
					}
				}
			}
		}
	}
	return nil, "", errors.New("singbox_stats_upgrade_required")
}

func (e Engine) lifecycleDir() string { return e.ManagedPaths().LifecycleDir }

func (e Engine) LifecycleReceipt(r LifecycleRequest) (LifecycleResult, error) {
	var result LifecycleResult
	if !r.Valid() {
		return result, errors.New("invalid_lifecycle_request")
	}
	if err := readJSON(filepath.Join(e.lifecycleDir(), r.TaskID+".json"), &result); err != nil {
		return result, err
	}
	if result.TaskID != r.TaskID || result.InstanceID != r.InstanceID || result.Epoch != r.Epoch || result.Kind != r.Kind || result.Fencing != r.Fencing {
		return LifecycleResult{}, errors.New("lifecycle_receipt_mismatch")
	}
	return result, nil
}

func (e Engine) Lifecycle(ctx context.Context, r LifecycleRequest) (LifecycleResult, error) {
	result := LifecycleResult{TaskID: r.TaskID, InstanceID: r.InstanceID, Epoch: r.Epoch, Kind: r.Kind, Fencing: r.Fencing, State: "unknown", ServiceState: "unknown", FinishedAt: time.Now().UTC()}
	if !r.Valid() || os.Geteuid() != 0 {
		return result, errors.New("invalid_lifecycle_request")
	}
	dir := e.lifecycleDir()
	if err := safeDir(dir, true); err != nil {
		return result, err
	}
	unlock, err := acquire(ctx, filepath.Join(dir, "operations.lock"))
	if err != nil {
		return result, err
	}
	defer unlock()
	if prior, err := e.LifecycleReceipt(r); err == nil {
		return prior, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	if err = e.checkLifecycleAuthority(r); err != nil {
		return result, err
	}
	path := filepath.Join(dir, r.TaskID+".json")
	if err = writeJSON(path, result); err != nil {
		return result, err
	}
	fencePath := filepath.Join(dir, r.InstanceID+".fence")
	var fence struct {
		Epoch   string
		Fencing uint64
	}
	if x := readJSON(fencePath, &fence); x != nil && !errors.Is(x, os.ErrNotExist) {
		return result, x
	}
	if (fence.Epoch != "" && fence.Epoch != r.Epoch) || fence.Fencing >= r.Fencing {
		err = errors.New("stale_lifecycle_task")
	} else {
		fence.Epoch = r.Epoch
		fence.Fencing = r.Fencing
		if err = writeJSON(fencePath, fence); err != nil {
			return result, err
		}
		if r.Kind == "install_singbox" {
			err = e.installSingbox(ctx, r, &result)
		} else if r.Kind == "restart_singbox" {
			err = e.restartSingbox(ctx, r, &result)
		} else {
			err = e.uninstallSingbox(ctx, r, &result)
		}
	}
	result.FinishedAt = time.Now().UTC()
	if err != nil {
		result.State = "failed_manual"
		if err.Error() == "singbox_restart_result_unknown" {
			result.State = "unknown"
		}
		result.ErrorCode = err.Error()
		if len(result.ErrorCode) > 100 || strings.ContainsAny(result.ErrorCode, "/\\\n") {
			result.ErrorCode = "singbox_local_operation_failed"
		}
	} else {
		result.State = "succeeded"
	}
	if x := writeJSON(path, result); x != nil {
		return result, x
	}
	return result, nil
}

func (e Engine) restartSingbox(ctx context.Context, request LifecycleRequest, result *LifecycleResult) error {
	if request.TargetVersion != "" && !SupportedSingboxVersion(request.TargetVersion) {
		return errors.New("unsupported_singbox_version")
	}
	unlock, err := e.locks(ctx, request.InstanceID)
	if err != nil {
		return errors.New("singbox_lock_failed")
	}
	defer unlock()
	dir, config, state, err := e.open(request.InstanceID)
	if err != nil {
		return errors.New("singbox_registration_unavailable")
	}
	result.Installed, result.Version = true, config.BinaryVersion
	if config.Epoch != request.Epoch || state.Fencing >= request.Fencing {
		return errors.New("stale_lifecycle_task")
	}
	if !SupportedSingboxVersion(config.BinaryVersion) {
		if err = e.pinInstanceBinaryLocked(ctx, dir, &config); err != nil {
			return err
		}
		result.Version = config.BinaryVersion
	}
	if state.LastResult != "succeeded" || state.CurrentVersion == "" || state.CurrentVersion != state.VerifiedVersion {
		return errors.New("singbox_recovery_required")
	}
	if target, x := os.Readlink(filepath.Join(dir, "current")); x != nil || target != "versions/"+state.CurrentVersion {
		return errors.New("current_pointer_drift")
	}
	if err = e.StartGate(request.InstanceID); err != nil {
		return errors.New("configuration_or_dependency_drift")
	}
	model, _, err := verifyVersion(dir, state.CurrentVersion)
	if err != nil {
		return errors.New("configuration_or_dependency_drift")
	}
	versionDir := filepath.Join(dir, "versions", state.CurrentVersion)
	if err = e.Runtime.Check(ctx, config, versionDir); err != nil {
		return errors.New("singbox_config_check_failed")
	}
	if err = e.Runtime.Restart(ctx, config, dir); err != nil {
		if ctx.Err() != nil {
			return errors.New("singbox_restart_result_unknown")
		}
		return errors.New("singbox_restart_failed")
	}
	if err = e.Runtime.Healthy(ctx, config, versionDir, model); err != nil {
		return errors.New("fresh_protocol_health_failed")
	}
	result.ServiceState = "running"
	return nil
}

func (e Engine) pinInstanceBinaryLocked(ctx context.Context, dir string, config *RuntimeConfig) error {
	expected := filepath.Join(e.ManagedPaths().SingboxDir, config.InstanceID, "sing-box")
	if config.Binary != expected {
		return errors.New("singbox_unmanaged_binary")
	}
	data, resolvedVer, err := e.lifecycleBinary(ctx, DefaultSingboxVersion)
	if err != nil {
		return err
	}
	if err = writeFile(config.Binary, data, 0755); err != nil {
		return errors.New("singbox_binary_write_failed")
	}
	_ = os.Chown(config.Binary, 0, 0)
	sum := sha256.Sum256(data)
	config.BinarySHA256 = hex.EncodeToString(sum[:])
	config.BinaryVersion = resolvedVer
	if err = writeJSON(filepath.Join(dir, "runtime.json"), *config); err != nil {
		return errors.New("singbox_initialization_failed")
	}
	return nil
}

func (e Engine) EnsurePinnedSingboxVersion(ctx context.Context) {
	if os.Geteuid() != 0 {
		return
	}
	entries, err := os.ReadDir(e.Root)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || !identifier.MatchString(entry.Name()) {
			continue
		}
		id := entry.Name()
		unlock, err := e.locks(ctx, id)
		if err != nil {
			continue
		}
		dir, config, state, err := e.open(id)
		if err == nil && !SupportedSingboxVersion(config.BinaryVersion) {
			if e.pinInstanceBinaryLocked(ctx, dir, &config) == nil && state.LastResult == "succeeded" && state.CurrentVersion != "" && state.CurrentVersion == state.VerifiedVersion {
				versionDir := filepath.Join(dir, "versions", state.CurrentVersion)
				if e.Runtime.Check(ctx, config, versionDir) == nil {
					_ = e.Runtime.Restart(ctx, config, dir)
				}
			}
		}
		unlock()
	}
}

func (e Engine) installSingbox(ctx context.Context, r LifecycleRequest, result *LifecycleResult) error {
	instDir := filepath.Join(e.Root, r.InstanceID)
	if _, err := os.Lstat(instDir); err == nil {
		_ = os.RemoveAll(instDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("instance_already_registered")
	}
	plist := filepath.Join("/Library/LaunchDaemons", "com.lineops.sing-box."+r.InstanceID+".plist")
	_ = exec.CommandContext(ctx, "/bin/launchctl", "bootout", "system", plist).Run()
	_ = os.Remove(plist)

	base := filepath.Join(e.ManagedPaths().SingboxDir, r.InstanceID)
	if err := safeDir(base, true); err != nil {
		return errors.New("singbox_directory_unsafe")
	}
	binary := filepath.Join(base, "sing-box")
	if _, err := os.Lstat(binary); err == nil {
		_ = os.Remove(binary)
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("singbox_binary_already_exists")
	}
	data, resolvedVer, err := e.lifecycleBinary(ctx, r.TargetVersion)
	if err != nil {
		return err
	}
	if err = writeFile(binary, data, 0755); err != nil {
		return errors.New("singbox_binary_write_failed")
	}
	_ = os.Chown(binary, 0, 0)
	if err = os.Chmod(base, 0755); err != nil {
		return errors.New("singbox_directory_permission_failed")
	}
	sum := sha256.Sum256(data)
	config := RuntimeConfig{
		TrafficAPI:     true,
		InstanceID:     r.InstanceID,
		Epoch:          r.Epoch,
		Binary:         binary,
		BinarySHA256:   hex.EncodeToString(sum[:]),
		BinaryVersion:  resolvedVer,
		RecoveryBinary: e.ManagedPaths().RecoveryBinary(),
		ServiceUser:    "daemon",
	}
	if err = Initialize(ctx, e.Root, config); err != nil {
		return errors.New("singbox_initialization_failed")
	}
	result.Installed = true
	result.Version = resolvedVer
	result.ServiceState = "stopped"
	return nil
}

func (e Engine) uninstallSingbox(ctx context.Context, r LifecycleRequest, result *LifecycleResult) error {
	unlock, err := e.locks(ctx, r.InstanceID)
	if err != nil {
		return errors.New("singbox_lock_failed")
	}
	defer unlock()
	dir, config, state, err := e.open(r.InstanceID)
	if err != nil {
		return errors.New("singbox_registration_unavailable")
	}
	if config.Epoch != r.Epoch || state.Fencing >= r.Fencing {
		return errors.New("stale_lifecycle_task")
	}
	if state.CurrentVersion != "" {
		data, err := readRegular(filepath.Join(dir, "versions", state.CurrentVersion, "config.json"))
		var c struct {
			Inbounds []json.RawMessage `json:"inbounds"`
		}
		if err != nil || json.Unmarshal(data, &c) != nil || len(c.Inbounds) != 0 {
			return errors.New("singbox_nodes_remain")
		}
	}
	_ = (SystemdRuntime{}).Stop(ctx, config)
	_ = os.Remove(darwinPlistPath(config))
	_ = os.Remove(config.Binary)
	_ = os.RemoveAll(dir)
	result.Installed = false
	result.ServiceState = "not_installed"
	return nil
}
