//go:build linux

package agentconfig

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func checkFile(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("config file must have a clean absolute path")
	}
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("config and parents must be root-owned, not writable by group/others, without symlinks")
		}
		if p == path && !info.Mode().IsRegular() {
			return errors.New("config must be a regular file")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}
