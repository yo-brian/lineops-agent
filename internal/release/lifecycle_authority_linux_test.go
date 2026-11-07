//go:build linux

package release

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDurableLifecycleAuthorityBlocksDelayedOriginalWithoutMutation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned metadata test")
	}
	base, err := os.MkdirTemp("/run", "lineops-lifecycle-authority-test-")
	if err != nil {
		t.Skip("protected test directory unavailable")
	}
	defer os.RemoveAll(base)
	e := Engine{Root: filepath.Join(base, "instances")}
	if err = os.Mkdir(e.Root, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(e.lifecycleDir(), 0700); err != nil {
		t.Fatal(err)
	}
	r := observationRequest()
	dir := filepath.Join(e.Root, r.InstanceID)
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = writeJSON(filepath.Join(dir, "runtime.json"), RuntimeConfig{InstanceID: r.InstanceID, Epoch: r.Epoch}); err != nil {
		t.Fatal(err)
	}
	if err = writeJSON(filepath.Join(dir, "state.json"), State{InstanceID: r.InstanceID, Epoch: r.Epoch}); err != nil {
		t.Fatal(err)
	}
	p := localLifecycleReader{e}
	if err = p.authorize(r); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(e.lifecycleAuthorityPath(r.InstanceID))
	if err != nil {
		t.Fatal(err)
	}
	if err = p.authorize(r); err != nil {
		t.Fatal("read-only retry rejected", err)
	}
	after, _ := os.ReadFile(e.lifecycleAuthorityPath(r.InstanceID))
	if string(stored) != string(after) {
		t.Fatal("same authority changed during retry")
	}
	// Runtime is intentionally nil. Even a regression cannot reach a service
	// restart, but must also not create original intent or fence metadata.
	_, err = e.Lifecycle(context.Background(), r.Original)
	if err == nil || err.Error() != "stale_lifecycle_task" {
		t.Fatal("delayed original was not revoked", err)
	}
	for _, name := range []string{r.Original.TaskID + ".json", r.InstanceID + ".fence"} {
		if _, err = os.Lstat(filepath.Join(e.lifecycleDir(), name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("delayed command changed original evidence", name)
		}
	}
	historical := LifecycleResult{TaskID: r.Original.TaskID, InstanceID: r.InstanceID, Epoch: r.Epoch, Kind: r.Original.Kind, Fencing: r.Original.Fencing, State: "unknown", ServiceState: "unknown", FinishedAt: time.Now().UTC()}
	if err = writeJSON(filepath.Join(e.lifecycleDir(), r.Original.TaskID+".json"), historical); err != nil {
		t.Fatal(err)
	}
	result, err := e.Lifecycle(context.Background(), r.Original)
	if err != nil || result != historical {
		t.Fatal("revocation changed historical receipt", result, err)
	}
	newer := r
	newer.TaskID = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
	newer.Fencing++
	if err = p.authorize(newer); err != nil {
		t.Fatal("new independent check rejected", err)
	}
	if err = p.authorize(r); err == nil {
		t.Fatal("older check reused authority")
	}
	if err = os.Chmod(e.lifecycleAuthorityPath(r.InstanceID), 0666); err != nil {
		t.Fatal(err)
	}
	if err = p.authorize(newer); err == nil {
		t.Fatal("unsafe authority ownership accepted")
	}
	if err = e.checkLifecycleAuthority(r.Original); err == nil {
		t.Fatal("unsafe authority enabled mutation")
	}
	if err = os.Chmod(e.lifecycleAuthorityPath(r.InstanceID), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(e.lifecycleAuthorityPath(r.InstanceID), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = p.authorize(newer); err == nil {
		t.Fatal("corrupt authority replaced")
	}
	if err = e.checkLifecycleAuthority(r.Original); err == nil {
		t.Fatal("corrupt authority enabled mutation")
	}
}
