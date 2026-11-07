//go:build !linux

package agentconfig

import (
	"errors"
	"os"
)

func checkFile(path string) error {
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() {
		return errors.New("config must be a regular file")
	}
	return nil
}
