//go:build linux

package agentbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lineops-agent/internal/release"
	"lineops-agent/internal/security"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLinuxUnixSocketPeerCredentialsAndRegistration(t *testing.T) {
	if os.Getenv("LINEOPS_TEST_EXECUTOR") != "1" || os.Geteuid() != 0 {
		t.Skip("requires explicitly enabled isolated Linux root UDS test")
	}
	base := "/run/lineops-bridge-test-" + security.ID()
	if e := os.Mkdir(base, 0755); e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(base)
	root := filepath.Join(base, "instances")
	os.Mkdir(root, 0711)
	instance := "isolated-instance"
	dir := filepath.Join(root, instance)
	os.Mkdir(dir, 0700)
	for name, value := range map[string]any{"runtime.json": release.RuntimeConfig{InstanceID: instance, Epoch: "test-epoch"}, "state.json": release.State{InstanceID: instance, Epoch: "test-epoch", LastResult: "unpublished"}} {
		data, _ := json.Marshal(value)
		if e := os.WriteFile(filepath.Join(dir, name), data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	socket := filepath.Join(base, "socket", "executor.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ServerConfig{Root: root, Socket: socket, AgentUID: 65534, AgentGID: 65534}) }()
	defer func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(3 * time.Second):
			t.Error("executor shutdown timed out")
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, e := os.Stat(socket); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket not created")
		}
		time.Sleep(20 * time.Millisecond)
	}
	client, e := New(socket)
	if e != nil {
		t.Fatal(e)
	}
	if e = client.Ready(context.Background()); e != nil {
		t.Fatal(e)
	}
	state, e := client.Status(context.Background(), instance)
	if e != nil || state.InstanceID != instance {
		t.Fatal("root status failed")
	}
	if _, e = client.Status(context.Background(), "../etc"); e == nil {
		t.Fatal("traversal accepted")
	}
	self, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(self)
	if e != nil {
		t.Fatal(e)
	}
	child := filepath.Join(base, "peer-test")
	if e = os.WriteFile(child, data, 0755); e != nil {
		t.Fatal(e)
	}
	for _, uid := range []uint32{65534, 65533} {
		cmd := exec.Command(child, "-test.run=^TestLinuxExecutorChild$")
		cmd.Env = []string{"LINEOPS_EXECUTOR_CHILD=1", "LINEOPS_SOCKET=" + socket, "LINEOPS_INSTANCE=" + instance, "LINEOPS_EXPECT_ALLOWED=" + fmt.Sprint(uid == 65534)}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: 65534}}
		output, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("peer credential test uid=%d: %s", uid, output)
		}
	}
}
func TestLinuxExecutorChild(t *testing.T) {
	if os.Getenv("LINEOPS_EXECUTOR_CHILD") != "1" {
		t.Skip("isolated peer subprocess only")
	}
	socket := os.Getenv("LINEOPS_SOCKET")
	allowed := os.Getenv("LINEOPS_EXPECT_ALLOWED") == "true"
	client, e := New(socket)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	e = client.Ready(ctx)
	if allowed {
		if e != nil {
			t.Fatal(e)
		}
		state, e := client.Status(ctx, os.Getenv("LINEOPS_INSTANCE"))
		if e != nil || state.LastResult != "unpublished" {
			t.Fatal("non-root registered Agent cannot read status")
		}
	} else {
		if e == nil {
			t.Fatal("same-group wrong UID was accepted")
		}
		var bridgeError *Error
		if !errors.As(e, &bridgeError) {
			t.Fatal("unexpected peer rejection")
		}
	}
}
