package agentmenu

import (
	"errors"
	"os"
	"path/filepath"
)

// Identity paths are fixed by the installer; never source the env file as shell
// code or send machine credentials to an interactively supplied origin.
func protectedRead(path string) ([]byte, error) {
	for current := path; ; current = filepath.Dir(current) {
		info, e := os.Lstat(current)
		if e != nil {
			return nil, e
		}
		if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return nil, errors.New("Agent 配置或身份路径存在不安全权限/符号链接")
		}
		if current == path && (!info.Mode().IsRegular() || info.Size() > 65536) {
			return nil, errors.New("Agent 配置或身份文件类型无效")
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return os.ReadFile(path)
}
