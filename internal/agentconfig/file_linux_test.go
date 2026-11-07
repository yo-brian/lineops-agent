//go:build linux

package agentconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedConfigRejectsWritableFilesAndSymlinks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership test")
	}
	dir, e := os.MkdirTemp("/opt", "lineops-config-test-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "config.yml")
	if e = os.WriteFile(p, []byte("schema_version: 1\npanel:\n  url: https://panel.example.com\n"), 0640); e != nil {
		t.Fatal(e)
	}
	if _, e = Load(p); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(p, 0660); e != nil {
		t.Fatal(e)
	}
	if _, e = Load(p); e == nil {
		t.Fatal("group-writable config accepted")
	}
	os.Chmod(p, 0640)
	link := filepath.Join(dir, "link.yml")
	if e = os.Symlink(p, link); e != nil {
		t.Fatal(e)
	}
	if _, e = Load(link); e == nil {
		t.Fatal("config symlink accepted")
	}
}
