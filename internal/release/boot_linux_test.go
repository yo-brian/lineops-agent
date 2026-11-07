//go:build linux

package release

import (
	"os"
	"testing"
)

func TestBootIDUsesInitViewAcrossServiceNamespaces(t *testing.T) {
	const initBoot = "62533601-3bb0-4ce1-aeac-e3e75d6ecfd9\n"
	for _, serviceBoot := range []string{
		"0a1e38e3-624e-4ff1-8237-a03fd55c5c51\n",
		"another-service-namespace\n",
	} {
		got := readBootID(func(path string) ([]byte, error) {
			if path == "/proc/1/root/proc/sys/kernel/random/boot_id" {
				return []byte(initBoot), nil
			}
			return []byte(serviceBoot), nil
		})
		if got != initBoot {
			t.Fatalf("namespace-dependent boot identity: %q", got)
		}
	}
	nextBoot := readBootID(func(string) ([]byte, error) { return []byte("next-boot\n"), nil })
	if nextBoot == initBoot {
		t.Fatal("actual reboot did not change boot identity")
	}
}

func TestBootIDFallsBackWhenInitViewUnavailable(t *testing.T) {
	for _, initError := range []error{os.ErrPermission, os.ErrNotExist} {
		got := readBootID(func(path string) ([]byte, error) {
			if path == "/proc/1/root/proc/sys/kernel/random/boot_id" {
				return nil, initError
			}
			return []byte("local-boot\n"), nil
		})
		if got != "local-boot\n" {
			t.Fatalf("fallback identity: %q", got)
		}
	}
}
