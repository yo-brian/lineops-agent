//go:build linux || darwin

package release

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func acquire(ctx context.Context, path string) (func(), error) {
	fd, e := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	for {
		e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = f.Close() }, nil
		}
		if !errors.Is(e, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, e
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(40 * time.Millisecond):
		}
	}
}
func bootID() string { return readBootID(os.ReadFile) }

// Service mount namespaces can expose a different boot_id from the container's
// init namespace. Always use PID 1's view so the publisher, startup gate and
// independent recovery agree, while an actual boot still changes the identity.
func readBootID(readFile func(string) ([]byte, error)) string {
	for _, path := range []string{
		"/proc/1/root/proc/sys/kernel/random/boot_id",
		"/proc/sys/kernel/random/boot_id",
	} {
		if b, err := readFile(path); err == nil && len(b) > 0 {
			return string(b)
		}
	}
	if out, err := exec.Command("/usr/sbin/sysctl", "-n", "kern.bootsessionuuid").Output(); err == nil {
		if s := strings.TrimSpace(string(out)); s != "" {
			return s
		}
	}
	return "darwin-boot"
}
