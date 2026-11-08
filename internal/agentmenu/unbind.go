package agentmenu

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func (m *menu) unbindPanel() error {
	fmt.Println("将停止 Agent 并取消自启，清除本机面板地址、身份凭据和待发送数据。面板上的资源与历史记录保留，Agent 将显示离线。")
	fmt.Println("保留 sing-box、节点配置、执行器和独立恢复／授权检查；已开始的本机任务与授权到期规则继续生效。重新绑定需使用面板的安装／注册流程。")
	if !m.confirm("解除面板绑定（保留节点）") {
		return nil
	}
	if m.panel != nil {
		m.panel.http.CloseIdleConnections()
		m.panel.token = ""
		m.panel = nil
	}
	if err := m.loadConfig(); err != nil {
		return err
	}
	configDir := "/etc/lineops-agent"
	if m.cfg != nil {
		configDir = "/etc/lineops"
		for _, dir := range []string{configDir, m.paths.AgentStateDir} {
			if info, e := os.Lstat(dir); e == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
				marker := filepath.Join(dir, ".lineops-owned")
				if _, me := os.Lstat(marker); errors.Is(me, os.ErrNotExist) {
					_ = os.WriteFile(marker, []byte("lineops-agent-v1\n"), 0400)
				}
			}
		}
	}
	if err := clearPanelBinding(m.paths.AgentStateDir, configDir, unbindSystemctl); err != nil {
		return err
	}
	fmt.Println("已解除本机面板绑定。Agent 已停止并取消自启，节点文件和服务保留。")
	return nil
}

func unbindSystemctl(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "systemctl", args...).Output()
	return string(b), err
}

// Only the fixed Agent state and configuration directories are passed by the
// menu. Roots keep removal anchored, and all targets are checked before stopping
// the Agent. Instance data, executors, recovery timers and binaries are untouched.
func clearPanelBinding(stateDir, configDir string, systemctl func(...string) (string, error)) error {
	state, err := bindingRoot(stateDir)
	if err != nil {
		return err
	}
	defer state.Close()
	config, err := bindingRoot(configDir)
	if err != nil {
		return err
	}
	defer config.Close()
	directory, err := state.Open(".")
	if err != nil {
		return err
	}
	entries, err := directory.ReadDir(-1)
	directory.Close()
	if err != nil {
		return err
	}
	var stateFiles []string
	for _, entry := range entries {
		if entry.Name() == ".lineops-owned" {
			continue
		}
		if err := bindingFile(state, entry.Name()); err != nil {
			return err
		}
		stateFiles = append(stateFiles, entry.Name())
	}
	configFiles := []string{"agent.env", "agent.env.new", "ca.pem", "config.yml", "config.yml.tmp"}
	for _, name := range configFiles {
		if err := bindingFile(config, name); err != nil {
			return err
		}
	}
	if _, err := systemctl("disable", "--now", "lineops-agent.service"); err != nil {
		return errors.New("Agent 停止或取消自启失败，未清除绑定数据；请查看服务状态后重试")
	}
	status, err := systemctl("show", "lineops-agent.service", "--property=ActiveState", "--property=MainPID", "--no-pager")
	if err != nil {
		return errors.New("无法确认 Agent 已停止，未清除绑定数据")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(status, "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			fields[key] = strings.TrimSpace(value)
		}
	}
	if (fields["ActiveState"] != "inactive" && fields["ActiveState"] != "failed") || fields["MainPID"] != "0" {
		return errors.New("Agent 尚未完全停止，未清除绑定数据")
	}
	// The Agent may have written new pending files during shutdown. Re-read the
	// directory rather than leaving an identity/rotation token behind.
	directory, err = state.Open(".")
	if err != nil {
		return err
	}
	entries, err = directory.ReadDir(-1)
	directory.Close()
	if err != nil {
		return err
	}
	stateFiles = stateFiles[:0]
	for _, entry := range entries {
		if entry.Name() != ".lineops-owned" {
			if err := bindingFile(state, entry.Name()); err != nil {
				return err
			}
			stateFiles = append(stateFiles, entry.Name())
		}
	}
	for _, target := range []struct {
		root  *os.Root
		files []string
	}{{config, configFiles}, {state, stateFiles}} {
		for _, name := range target.files {
			if err := target.root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
				return errors.New("绑定数据清理未完成，Agent 已停止；请检查文件权限后重试解除绑定")
			}
		}
		f, err := target.root.Open(".")
		if err != nil {
			return err
		}
		err = f.Sync()
		f.Close()
		if err != nil {
			return errors.New("绑定数据已清理，但目录持久化未确认；请重试解除绑定")
		}
	}
	return nil
}

func bindingRoot(path string) (*os.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("Agent 数据目录无效")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("Agent 数据目录不存在或包含符号链接，未清除绑定数据")
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	if err := bindingFile(root, ".lineops-owned"); err != nil {
		root.Close()
		return nil, err
	}
	b, err := root.ReadFile(".lineops-owned")
	if err != nil || string(b) != "lineops-agent-v1\n" {
		root.Close()
		return nil, errors.New("Agent 数据目录缺少有效安装标记，未清除绑定数据")
	}
	return root, nil
}

func bindingFile(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("Agent 绑定目录含异常文件或目录，未清除绑定数据")
	}
	return nil
}
