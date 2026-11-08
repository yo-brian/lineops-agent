//go:build linux

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
	"strings"
	"time"
)

func (e Engine) lifecycleBinary(ctx context.Context) ([]byte, error) {
	candidates := []string{
		filepath.Join(e.ManagedPaths().AgentBinDir, "lineops-singbox"),
		filepath.Join(e.ManagedPaths().AgentBinDir, "sing-box"),
		"/usr/local/bin/sing-box",
		"/usr/bin/sing-box",
	}
	for _, path := range candidates {
		if err := protectedProgram(path); err != nil {
			continue
		}
		out, err := exec.CommandContext(ctx, path, "version").Output()
		if err != nil || !outputHasVersion(out, "1.14.0") || !strings.Contains(string(out), "with_v2ray_api") {
			continue
		}
		return readBinary(path)
	}
	return nil, errors.New("singbox_stats_upgrade_required")
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
	// Existing receipts remain readable above, but delayed commands whose
	// authority was revoked by reconciliation must never begin side effects.
	if err = e.checkLifecycleAuthority(r); err != nil {
		return result, err
	}
	// Persist uncertain intent BEFORE side effects. A crash never causes a blind replay.
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
	if state.LastResult != "succeeded" || state.CurrentVersion == "" || state.CurrentVersion != state.VerifiedVersion {
		return errors.New("singbox_recovery_required")
	}
	if target, x := os.Readlink(filepath.Join(dir, "current")); x != nil || target != "versions/"+state.CurrentVersion {
		return errors.New("current_pointer_drift")
	}
	if journal, x := activeJournal(dir); x == nil && pending(journal) || x != nil && !errors.Is(x, os.ErrNotExist) {
		return errors.New("singbox_recovery_required")
	}
	// Validate the exact existing version and current authorization. Never publish
	// a new version or replay historical policy as a side effect of restarting.
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

func (e Engine) installSingbox(ctx context.Context, r LifecycleRequest, result *LifecycleResult) error {
	instDir := filepath.Join(e.Root, r.InstanceID)
	if _, err := os.Lstat(instDir); err == nil {
		_ = os.RemoveAll(instDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("instance_already_registered")
	}
	for _, u := range []string{"lineops-sing-box-" + r.InstanceID + ".service", "lineops-policy-" + r.InstanceID + ".timer", "lineops-policy-" + r.InstanceID + ".service"} {
		_ = command(ctx, "/usr/bin/systemctl", "disable", "--now", u)
		_ = os.Remove(filepath.Join("/etc/systemd/system", u))
	}
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
	data, err := e.lifecycleBinary(ctx)
	if err != nil {
		return err
	}
	if err = writeFile(binary, data, 0755); err != nil {
		return errors.New("singbox_binary_write_failed")
	}
	if err = os.Chmod(base, 0755); err != nil {
		return errors.New("singbox_directory_permission_failed")
	}
	sum := sha256.Sum256(data)
	config := RuntimeConfig{TrafficAPI: true, InstanceID: r.InstanceID, Epoch: r.Epoch, Binary: binary, BinarySHA256: hex.EncodeToString(sum[:]), BinaryVersion: "1.14.0", RecoveryBinary: e.ManagedPaths().RecoveryBinary(), ServiceUser: "lineops-singbox"}
	if err = Initialize(ctx, e.Root, config); err != nil {
		return errors.New("singbox_initialization_failed")
	}
	result.Installed = true
	result.Version = "1.14.0"
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
	if state.LastResult != "succeeded" && state.LastResult != "unpublished" {
		return errors.New("singbox_recovery_required")
	}
	if state.CurrentVersion != "" {
		if state.CurrentVersion != state.VerifiedVersion {
			return errors.New("singbox_cleanup_unverified")
		}
		data, err := readRegular(filepath.Join(dir, "versions", state.CurrentVersion, "config.json"))
		var c struct {
			Inbounds []json.RawMessage `json:"inbounds"`
		}
		if err != nil || json.Unmarshal(data, &c) != nil || len(c.Inbounds) != 0 {
			return errors.New("singbox_nodes_remain")
		}
	}
	expected := filepath.Join(e.ManagedPaths().SingboxDir, r.InstanceID, "sing-box")
	if config.Binary != expected {
		return errors.New("singbox_unmanaged_binary")
	}
	if err = runtimeValid(ctx, config); err != nil {
		return errors.New("singbox_binary_drift")
	}
	if err = verifyUnit(config, dir); err != nil {
		return errors.New("singbox_unit_drift")
	}
	for suffix, content := range map[string]string{".service": policyServiceContent(config, e.Root), ".timer": policyTimerContent(config)} {
		data, err := readRegular(filepath.Join("/etc/systemd/system", "lineops-policy-"+r.InstanceID+suffix))
		if err != nil || string(data) != content {
			return errors.New("singbox_policy_unit_drift")
		}
	}
	if err = removeTrafficTable(ctx, r.InstanceID); err != nil {
		return errors.New("singbox_traffic_cleanup_failed")
	}
	units := []string{"lineops-policy-" + r.InstanceID + ".timer", "lineops-policy-" + r.InstanceID + ".service", unit(config)}
	for _, name := range units {
		if err = command(ctx, "/usr/bin/systemctl", "stop", name); err != nil {
			return errors.New("singbox_stop_failed")
		}
	}
	for _, name := range []string{units[0], units[2]} {
		if err = command(ctx, "/usr/bin/systemctl", "disable", name); err != nil {
			return errors.New("singbox_disable_failed")
		}
	}
	for _, name := range units {
		if err = os.Remove(filepath.Join("/etc/systemd/system", name)); err != nil {
			return errors.New("singbox_unit_remove_failed")
		}
	}
	if err = command(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return errors.New("singbox_daemon_reload_failed")
	}
	if err = os.Remove(expected); err != nil {
		return errors.New("singbox_binary_remove_failed")
	}
	if err = os.RemoveAll(dir); err != nil {
		return errors.New("singbox_config_remove_failed")
	}
	result.Installed = false
	result.ServiceState = "not_installed"
	return nil
}
