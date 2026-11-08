//go:build linux

package agentmenu

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func unbindFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	state, config := filepath.Join(root, "agent-state"), filepath.Join(root, "agent-config")
	for _, dir := range []string{state, config} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".lineops-owned"), []byte("lineops-agent-v1\n"), 0400); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"identity.json", "enrollment-pending.json", "rotation-pending.json", "receipt-old.json", "inflight-release-old.json", ".pending-token"} {
		if err := os.WriteFile(filepath.Join(state, name), []byte("old-panel-data"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"config.yml", "config.yml.tmp", "ca.pem"} {
		if err := os.WriteFile(filepath.Join(config, name), []byte("old-panel-config"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root, state, config
}

func TestUnbindPreservesNodesAndClearsShutdownWrites(t *testing.T) {
	root, state, config := unbindFixture(t)
	// These model data outside the Agent binding directories. No sing-box unit
	// or executor operation is permitted while removing the panel binding.
	sentinels := []string{
		filepath.Join(root, "instances", "node", "config.json"),
		filepath.Join(root, "instances", "node", "policies.json"),
		filepath.Join(root, "bin", "sing-box"),
		filepath.Join(config, "operator-note"),
	}
	for _, path := range sentinels {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var calls [][]string
	control := func(args ...string) (string, error) {
		calls = append(calls, args)
		if args[0] == "disable" {
			// A final Agent write during shutdown must also be cleared.
			return "", os.WriteFile(filepath.Join(state, "stale-rotation-pending.json"), []byte("last-token"), 0600)
		}
		return "MainPID=0\nActiveState=inactive\n", nil
	}
	if err := clearPanelBinding(state, config, control); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"disable", "--now", "lineops-agent.service"},
		{"show", "lineops-agent.service", "--property=ActiveState", "--property=MainPID", "--no-pager"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("unexpected service operations: %v", calls)
	}
	entries, err := os.ReadDir(state)
	if err != nil || len(entries) != 1 || entries[0].Name() != ".lineops-owned" {
		t.Fatalf("binding state remains: %v, %v", entries, err)
	}
	for _, name := range []string{"config.yml", "config.yml.tmp", "ca.pem"} {
		if _, err := os.Lstat(filepath.Join(config, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("config remains: %s, %v", name, err)
		}
	}
	for _, path := range sentinels {
		if b, err := os.ReadFile(path); err != nil || string(b) != "preserve" {
			t.Fatalf("node/unrelated file changed: %s, %v", path, err)
		}
	}
	// Repeating an interrupted or already completed unbind remains possible.
	if err := clearPanelBinding(state, config, func(...string) (string, error) {
		return "ActiveState=inactive\nMainPID=0\n", nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestUnbindRetainsCredentialsUntilAgentStopped(t *testing.T) {
	for _, failure := range []string{"stop", "show", "active", "pid", "missing-status"} {
		t.Run(failure, func(t *testing.T) {
			_, state, config := unbindFixture(t)
			control := func(args ...string) (string, error) {
				if args[0] == "disable" {
					if failure == "stop" {
						return "", errors.New("stop failed")
					}
					return "", nil
				}
				switch failure {
				case "show":
					return "", errors.New("status failed")
				case "active":
					return "ActiveState=active\nMainPID=0\n", nil
				case "pid":
					return "ActiveState=inactive\nMainPID=123\n", nil
				default:
					return "", nil
				}
			}
			if err := clearPanelBinding(state, config, control); err == nil {
				t.Fatal("unconfirmed stop accepted")
			}
			for _, path := range []string{filepath.Join(state, "identity.json"), filepath.Join(config, "config.yml")} {
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("credentials deleted before stop: %v", err)
				}
			}
		})
	}
}

func TestUnbindRejectsUnsafeTargetsBeforeServiceChanges(t *testing.T) {
	for _, unsafe := range []string{"directory", "symlink-file", "symlink-root", "marker"} {
		t.Run(unsafe, func(t *testing.T) {
			root, state, config := unbindFixture(t)
			var err error
			switch unsafe {
			case "directory":
				err = os.Mkdir(filepath.Join(state, "unexpected-dir"), 0700)
			case "symlink-file":
				err = os.Symlink(filepath.Join(config, "config.yml"), filepath.Join(state, "outside-link"))
			case "symlink-root":
				link := filepath.Join(root, "state-link")
				err = os.Symlink(state, link)
				state = link
			case "marker":
				err = os.Remove(filepath.Join(state, ".lineops-owned"))
			}
			if err != nil {
				t.Fatal(err)
			}
			called := false
			if err := clearPanelBinding(state, config, func(...string) (string, error) {
				called = true
				return "", nil
			}); err == nil || called {
				t.Fatalf("unsafe target touched service: %v, %t", err, called)
			}
			if _, err := os.Stat(filepath.Join(config, "config.yml")); err != nil {
				t.Fatal("unsafe preflight changed config")
			}
		})
	}
}

func TestUnbindCancelDoesNotConnectToPanel(t *testing.T) {
	m := &menu{in: bufio.NewReader(strings.NewReader("NO\n"))}
	if err := m.action("15"); err != nil || m.panel != nil {
		t.Fatalf("offline cancel failed: %v", err)
	}
}
