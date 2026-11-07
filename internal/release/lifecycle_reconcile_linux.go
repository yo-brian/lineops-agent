//go:build linux

package release

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

type localLifecycleReader struct{ Engine }

func (e Engine) LifecycleReconcile(ctx context.Context, r LifecycleReconcileRequest) (LifecycleObservation, error) {
	if os.Geteuid() != 0 || e.Runtime == nil {
		return LifecycleObservation{}, errors.New("lifecycle_executor_unavailable")
	}
	return reconcileLifecycle(ctx, r, localLifecycleReader{e})
}

func protectedLifecyclePath(path string, directory bool) error {
	if err := safeDir(filepath.Dir(path), false); err != nil {
		return err
	}
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 || (p == path && !directory && !info.Mode().IsRegular()) || ((p != path || directory) && !info.IsDir()) || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("lifecycle_ownership_drift")
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}

func (p localLifecycleReader) lock(ctx context.Context, r LifecycleReconcileRequest) (func(), error) {
	// Same ordering as lifecycle mutation and publication. Only lock/authority
	// metadata is written; installation, receipt, fence and service state stay intact.
	if err := protectedLifecyclePath(p.lifecycleDir(), true); err != nil {
		return nil, err
	}
	unlock, err := acquire(ctx, filepath.Join(p.lifecycleDir(), "operations.lock"))
	if err != nil {
		return nil, err
	}
	if err = protectedLifecyclePath(p.Root, true); err != nil {
		unlock()
		return nil, err
	}
	host, err := acquire(ctx, filepath.Join(p.Root, "host-ports.lock"))
	if err != nil {
		unlock()
		return nil, err
	}
	all := func() { host(); unlock() }
	dir := filepath.Join(p.Root, r.InstanceID)
	if _, err = os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return all, nil
	}
	if err != nil {
		all()
		return nil, err
	}
	if err = protectedLifecyclePath(dir, true); err != nil {
		all()
		return nil, err
	}
	instance, err := acquire(ctx, filepath.Join(dir, "instance.lock"))
	if err != nil {
		all()
		return nil, err
	}
	return func() { instance(); all() }, nil
}

func (p localLifecycleReader) receipt(r LifecycleRequest) (LifecycleResult, error) {
	if err := protectedLifecyclePath(filepath.Join(p.lifecycleDir(), r.TaskID+".json"), false); err != nil {
		return LifecycleResult{}, err
	}
	return p.LifecycleReceipt(r)
}

func (p localLifecycleReader) fence(id string) (string, uint64, error) {
	path := filepath.Join(p.lifecycleDir(), id+".fence")
	if err := protectedLifecyclePath(path, false); err != nil {
		return "", 0, err
	}
	var value struct {
		Epoch   string
		Fencing uint64
	}
	err := readJSON(path, &value)
	if err == nil && (!lifecycleID.MatchString(value.Epoch) || value.Fencing == 0 || value.Fencing >= 1<<63) {
		err = errors.New("lifecycle_fence_invalid")
	}
	return value.Epoch, value.Fencing, err
}

func (e Engine) lifecycleAuthorityPath(id string) string {
	return filepath.Join(e.lifecycleDir(), id+".reconcile-authority.json")
}

func (e Engine) readLifecycleAuthority(id string) (lifecycleReconcileAuthority, error) {
	var authority lifecycleReconcileAuthority
	path := e.lifecycleAuthorityPath(id)
	if err := protectedLifecyclePath(path, false); err != nil {
		return authority, err
	}
	if err := readJSON(path, &authority); err != nil {
		return authority, err
	}
	if !authority.valid() || authority.InstanceID != id {
		return authority, errors.New("invalid_lifecycle_reconcile_authority")
	}
	return authority, nil
}

func (p localLifecycleReader) authorize(r LifecycleReconcileRequest) error {
	// Do not pin a foreign deployment epoch into authority metadata. An existing
	// registration proves it directly; after removal only the retained fence can.
	dir := filepath.Join(p.Root, r.InstanceID)
	if _, err := os.Lstat(dir); err == nil {
		for _, name := range []string{"runtime.json", "state.json"} {
			if err = protectedLifecyclePath(filepath.Join(dir, name), false); err != nil {
				return err
			}
		}
		_, config, state, err := p.open(r.InstanceID)
		if err != nil {
			return err
		}
		if config.Epoch != r.Epoch || lifecyclePublicationError(r, state, nil) != "" {
			return errors.New("stale_lifecycle_observation")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		epoch, fencing, err := p.fence(r.InstanceID)
		if err != nil || epoch != r.Epoch || fencing > r.Original.Fencing {
			return errors.New("lifecycle_absence_epoch_unverified")
		}
	} else {
		return err
	}
	prior, err := p.readLifecycleAuthority(r.InstanceID)
	if err == nil {
		if !prior.permitsObservation(r) {
			return errors.New("stale_lifecycle_reconcile_authority")
		}
		if prior.Fencing == r.Fencing {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	authority := lifecycleReconcileAuthority{TaskID: r.TaskID, InstanceID: r.InstanceID, Epoch: r.Epoch, Fencing: r.Fencing, OriginalTaskID: r.Original.TaskID, OriginalFencing: r.Original.Fencing}
	return writeJSON(p.lifecycleAuthorityPath(r.InstanceID), authority)
}

func (e Engine) checkLifecycleAuthority(r LifecycleRequest) error {
	authority, err := e.readLifecycleAuthority(r.InstanceID)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("lifecycle_reconcile_authority_unavailable")
	}
	if !authority.permitsLifecycle(r) {
		return errors.New("stale_lifecycle_task")
	}
	return nil
}

func (p localLifecycleReader) observe(ctx context.Context, request LifecycleReconcileRequest) (bool, string, string, error) {
	fail := func(code string) (bool, string, string, error) { return false, "", "unknown", errors.New(code) }
	dir := filepath.Join(p.Root, request.InstanceID)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if err = p.verifyAbsent(ctx, request.InstanceID); err != nil {
			return false, "", "unknown", err
		}
		return false, "", "not_installed", nil
	}
	for _, name := range []string{"runtime.json", "state.json"} {
		if err := protectedLifecyclePath(filepath.Join(dir, name), false); err != nil {
			return fail("lifecycle_ownership_drift")
		}
	}
	_, config, state, err := p.open(request.InstanceID)
	if err != nil {
		return fail("singbox_registration_unavailable")
	}
	journal, err := activeJournal(dir)
	var evidence *Journal
	if err == nil {
		if err = protectedLifecyclePath(filepath.Join(dir, "journal.json"), false); err != nil {
			return fail("singbox_recovery_required")
		}
		evidence = &journal
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail("singbox_recovery_required")
	}
	if code := lifecyclePublicationError(request, state, evidence); code != "" {
		return fail(code)
	}
	if config.Binary != filepath.Join(p.ManagedPaths().SingboxDir, request.InstanceID, "sing-box") || config.RecoveryBinary != p.ManagedPaths().RecoveryBinary() || config.ServiceUser != "lineops-singbox" {
		return fail("singbox_unmanaged_binary")
	}
	if err = runtimeValid(ctx, config); err != nil {
		return fail("singbox_binary_drift")
	}
	units := map[string]string{
		unit(config): serviceContent(config, dir),
		"lineops-policy-" + request.InstanceID + ".service": policyServiceContent(config, p.Root),
		"lineops-policy-" + request.InstanceID + ".timer":   policyTimerContent(config),
	}
	var service map[string]string
	for name, content := range units {
		path := filepath.Join("/etc/systemd/system", name)
		if err = protectedLifecyclePath(path, false); err != nil {
			return fail("singbox_unit_drift")
		}
		data, readErr := readRegular(path)
		values, showErr := lifecycleUnitStatus(ctx, name)
		if readErr != nil || string(data) != content || showErr != nil || values["LoadState"] != "loaded" || values["FragmentPath"] != path || values["DropInPaths"] != "" || values["NeedDaemonReload"] != "no" {
			return fail("singbox_unit_drift")
		}
		if name == unit(config) {
			service = values
		}
		if name == "lineops-policy-"+request.InstanceID+".timer" && (values["ActiveState"] != "active" || values["UnitFileState"] != "enabled") {
			return fail("singbox_policy_guard_unverified")
		}
	}
	if state.LastResult == "unpublished" && state.CurrentVersion == "" && state.VerifiedVersion == "" && state.Generation == 0 && state.Fencing == 0 {
		if _, err = os.Lstat(filepath.Join(dir, "current")); !errors.Is(err, os.ErrNotExist) {
			return fail("current_pointer_drift")
		}
		if _, err = os.Lstat(filepath.Join(dir, "policies.json")); !errors.Is(err, os.ErrNotExist) {
			return fail("singbox_initialization_unverified")
		}
		if protectedLifecyclePath(filepath.Join(dir, "versions"), true) != nil {
			return fail("lifecycle_ownership_drift")
		}
		versions, readErr := os.ReadDir(filepath.Join(dir, "versions"))
		if readErr != nil || len(versions) != 0 || service["ActiveState"] != "inactive" || service["SubState"] != "dead" || service["MainPID"] != "0" || service["ControlPID"] != "0" {
			return fail("singbox_initialization_unverified")
		}
		return true, config.BinaryVersion, "stopped", nil
	}
	if state.LastResult != "succeeded" || service["ActiveState"] != "active" || service["SubState"] != "running" || service["MainPID"] == "" || service["MainPID"] == "0" || service["ControlPID"] != "0" {
		return fail("singbox_current_state_unverified")
	}
	if !identifier.MatchString(state.CurrentVersion) {
		return fail("configuration_or_dependency_drift")
	}
	versionDir := filepath.Join(dir, "versions", state.CurrentVersion)
	if protectedLifecyclePath(versionDir, true) != nil {
		return fail("lifecycle_ownership_drift")
	}
	entries, err := os.ReadDir(versionDir)
	if err != nil {
		return fail("configuration_or_dependency_drift")
	}
	for _, entry := range entries {
		if protectedLifecyclePath(filepath.Join(versionDir, entry.Name()), false) != nil {
			return fail("lifecycle_ownership_drift")
		}
	}
	if _, err = p.verifyStatusLocked(ctx, request.InstanceID); err != nil {
		return fail("fresh_protocol_health_failed")
	}
	return true, config.BinaryVersion, "running", nil
}

func lifecycleUnitStatus(ctx context.Context, name string) (map[string]string, error) {
	data, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", name, "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,FragmentPath,DropInPaths,NeedDaemonReload,UnitFileState", "--no-pager").Output()
	if err != nil || len(data) > 64<<10 {
		return nil, errors.New("systemd_observation_unavailable")
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = value
		}
	}
	return values, nil
}

func (p localLifecycleReader) verifyAbsent(ctx context.Context, id string) error {
	fail := func() error { return errors.New("singbox_absence_unverified") }
	// An empty binary directory is retained by the existing uninstaller. Any
	// file, symlink, config directory, unit alias/drop-in or running unit blocks proof.
	base := filepath.Join(p.ManagedPaths().SingboxDir, id)
	if info, err := os.Lstat(base); err == nil {
		if !info.IsDir() || protectedLifecyclePath(base, true) != nil {
			return fail()
		}
		entries, err := os.ReadDir(base)
		if err != nil || len(entries) != 0 {
			return fail()
		}
	} else if !errors.Is(err, os.ErrNotExist) || safeDir(filepath.Dir(base), false) != nil {
		return fail()
	}
	for _, name := range []string{"lineops-sing-box-" + id + ".service", "lineops-policy-" + id + ".service", "lineops-policy-" + id + ".timer"} {
		for _, root := range []string{"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"} {
			for _, suffix := range []string{name, name + ".d", "multi-user.target.wants/" + name, "timers.target.wants/" + name} {
				if _, err := os.Lstat(filepath.Join(root, suffix)); !errors.Is(err, os.ErrNotExist) {
					return fail()
				}
			}
		}
		values, err := lifecycleUnitStatus(ctx, name)
		if err != nil || values["LoadState"] != "not-found" || values["ActiveState"] != "inactive" || values["FragmentPath"] != "" || values["DropInPaths"] != "" || (values["MainPID"] != "" && values["MainPID"] != "0") || (values["ControlPID"] != "" && values["ControlPID"] != "0") {
			return fail()
		}
	}
	guards, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "list-units", "--all", "--plain", "--no-legend", "--no-pager", "--full", "lineops-recover-"+id+"-*").Output()
	if err != nil || strings.TrimSpace(string(guards)) != "" {
		return errors.New("singbox_recovery_unit_remains")
	}
	processes, err := os.ReadDir("/proc")
	if err != nil {
		return fail()
	}
	for _, process := range processes {
		if !process.IsDir() || strings.Trim(process.Name(), "0123456789") != "" {
			continue
		}
		if ctx.Err() != nil {
			return fail()
		}
		binary, err := os.Readlink(filepath.Join("/proc", process.Name(), "exe"))
		if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ESRCH) {
			return fail()
		}
		if strings.HasPrefix(binary, base+"/") {
			return errors.New("singbox_process_remains")
		}
	}
	// nft's absence is not evidence that an old kernel table was removed.
	binary := "/usr/sbin/nft"
	if _, err := os.Stat(binary); err != nil {
		binary = "/sbin/nft"
	}
	if protectedProgram(binary) != nil {
		return errors.New("singbox_traffic_absence_unverified")
	}
	data, err := exec.CommandContext(ctx, binary, "-j", "list", "tables").Output()
	var snapshot nftSnapshot
	if err != nil || len(data) > 8<<20 || json.Unmarshal(data, &snapshot) != nil || snapshot.NFTables == nil {
		return errors.New("singbox_traffic_absence_unverified")
	}
	for _, entry := range snapshot.NFTables {
		if entry.Table != nil && entry.Table.Name == "lo_traffic_"+strings.ReplaceAll(id, "-", "") {
			return errors.New("singbox_traffic_table_remains")
		}
	}
	return nil
}
