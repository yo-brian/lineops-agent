//go:build linux

package agentmenu

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBBRBackupRestoreAndRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "restore", true: "rollback"}[fail], func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "menu")
			values := map[string]string{"net.ipv4.tcp_congestion_control": "cubic", "net.core.default_qdisc": "fq_codel", "net.ipv4.tcp_available_congestion_control": "cubic bbr"}
			cmd := func(name string, args ...string) (string, error) {
				if name != "sysctl" {
					t.Fatal(name)
				}
				if args[0] == "-n" {
					return values[args[1]], nil
				}
				k, v, _ := strings.Cut(args[1], "=")
				if fail && v == "bbr" {
					return "", errors.New("rejected")
				}
				values[k] = v
				return "", nil
			}
			e := configureBBR(dir, true, cmd)
			if fail {
				if e == nil || values["net.core.default_qdisc"] != "fq_codel" || values["net.ipv4.tcp_congestion_control"] != "cubic" {
					t.Fatal("failed rollback", e, values)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = configureBBR(dir, true, cmd); e != nil {
				t.Fatal(e)
			}
			if e = configureBBR(dir, false, cmd); e != nil {
				t.Fatal(e)
			}
			if values["net.ipv4.tcp_congestion_control"] != "cubic" || values["net.core.default_qdisc"] != "fq_codel" {
				t.Fatal(values)
			}
			if _, e = os.Stat(filepath.Join(dir, "before.json")); !os.IsNotExist(e) {
				t.Fatal("backup not removed")
			}
		})
	}
}

func TestBBRRejectsSymlinkAndUnsupportedKernel(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "other")
	if e := os.Mkdir(target, 0700); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(root, "link")
	if e := os.Symlink(target, link); e != nil {
		t.Fatal(e)
	}
	cmd := func(name string, args ...string) (string, error) {
		if name == "modprobe" {
			return "", errors.New("unsupported")
		}
		if args[0] == "-w" {
			t.Fatal("changed unsupported kernel")
		}
		if args[1] == "net.core.default_qdisc" {
			return "fq_codel", nil
		}
		return "cubic", nil
	}
	if e := configureBBR(link, true, cmd); e == nil {
		t.Fatal("accepted symlink")
	}
	if e := configureBBR(filepath.Join(root, "menu"), true, cmd); e == nil {
		t.Fatal("accepted unsupported kernel")
	}
}
