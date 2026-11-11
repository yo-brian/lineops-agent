//go:build darwin

package release

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type localLifecycleReader struct{ Engine }

func (e Engine) LifecycleReconcile(ctx context.Context, r LifecycleReconcileRequest) (LifecycleObservation, error) {
	if os.Geteuid() != 0 || e.Runtime == nil {
		return LifecycleObservation{}, errors.New("lifecycle_executor_unavailable")
	}
	return reconcileLifecycle(ctx, r, localLifecycleReader{e})
}

func (p localLifecycleReader) lock(ctx context.Context, r LifecycleReconcileRequest) (func(), error) {
	if err := safeDir(p.lifecycleDir(), true); err != nil {
		return nil, err
	}
	unlock, err := acquire(ctx, filepath.Join(p.lifecycleDir(), "operations.lock"))
	if err != nil {
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
	instance, err := acquire(ctx, filepath.Join(dir, "instance.lock"))
	if err != nil {
		all()
		return nil, err
	}
	return func() { instance(); all() }, nil
}

func (p localLifecycleReader) receipt(r LifecycleRequest) (LifecycleResult, error) {
	return p.LifecycleReceipt(r)
}

func (p localLifecycleReader) fence(id string) (string, uint64, error) {
	path := filepath.Join(p.lifecycleDir(), id+".fence")
	var value struct {
		Epoch   string
		Fencing uint64
	}
	err := readJSON(path, &value)
	return value.Epoch, value.Fencing, err
}

func (e Engine) lifecycleAuthorityPath(id string) string {
	return filepath.Join(e.lifecycleDir(), id+".reconcile-authority.json")
}

func (e Engine) readLifecycleAuthority(id string) (lifecycleReconcileAuthority, error) {
	var authority lifecycleReconcileAuthority
	if err := readJSON(e.lifecycleAuthorityPath(id), &authority); err != nil {
		return authority, err
	}
	if !authority.valid() || authority.InstanceID != id {
		return authority, errors.New("invalid_lifecycle_reconcile_authority")
	}
	return authority, nil
}

func (p localLifecycleReader) authorize(r LifecycleReconcileRequest) error {
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
	dir := filepath.Join(p.Root, request.InstanceID)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return false, "", "not_installed", nil
	}
	_, config, _, err := p.open(request.InstanceID)
	if err != nil {
		return false, "", "unknown", errors.New("singbox_registration_unavailable")
	}
	out, err := exec.CommandContext(ctx, "/bin/launchctl", "print", "system/"+darwinLabel(config)).Output()
	state := "stopped"
	if err == nil && strings.Contains(string(out), "state = running") {
		state = "running"
	}
	return true, config.BinaryVersion, state, nil
}
