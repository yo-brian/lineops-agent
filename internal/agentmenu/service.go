package agentmenu

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/goccy/go-yaml"
	"lineops-agent/internal/agentconfig"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Command exposes only fixed administrative actions; it never accepts a unit
// name, shell fragment, configuration path, or remote program from the caller.
func Command(name string) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("请在 Linux VPS 上使用 sudo lineops-agent")
	}
	m := &menu{in: bufio.NewReader(os.Stdin)}
	defer func() {
		if m.panel != nil {
			m.panel.http.CloseIdleConnections()
		}
	}()
	switch name {
	case "config":
		return m.action("16")
	case "status":
		return m.action("1")
	case "log":
		return m.action("8")
	case "singbox-log":
		return m.action("12")
	case "singbox-restart":
		return m.action("11")
	case "bbr":
		return m.action("9")
	case "unbind":
		return m.action("15")
	case "start", "stop", "restart", "enable", "disable":
		return m.controlAgent(name)
	default:
		return errors.New("可用命令：menu、config、status、log、singbox-log、singbox-restart、start、stop、restart、enable、disable、bbr、unbind")
	}
}

func (m *menu) printHeader() {
	_ = m.loadConfig()
	panelURL := "未配置"
	bindingID := "未绑定"
	if m.cfg != nil {
		if m.cfg.Panel.URL != "" {
			panelURL = m.cfg.Panel.URL
		}
		if m.cfg.Binding.VPSID != "" {
			bindingID = "VPS:" + m.cfg.Binding.VPSID
		} else if m.cfg.Binding.NodeID != "" {
			bindingID = "Node:" + m.cfg.Binding.NodeID
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	agentState := "unknown"
	if out, err := exec.CommandContext(ctx, "systemctl", "is-active", "lineops-agent.service").Output(); err == nil {
		agentState = strings.TrimSpace(string(out))
	}
	fmt.Printf("\n================ LineOps VPS 管理 ================\n配置文件: %s | 面板: %s\n绑定标识: %s | Agent 状态: %s\n==================================================\n", agentconfig.DefaultFile, clean(panelURL), clean(bindingID), clean(agentState))
}

func (m *menu) configureConfigYML() error {
	_ = m.loadConfig()
	cfg := agentconfig.Default()
	if m.cfg != nil {
		cfg = *m.cfg
	}
	cfg.Paths = agentconfig.NewPaths()
	fmt.Println("配置 /etc/lineops/config.yml（类似 xboard-node，填写面板网址、API Key、VPS ID 或节点 ID 即可自动通信与接管）：")
	urlInput, err := m.read("面板通信网址 (HTTPS Origin，如 https://panel.example.com)", cfg.Panel.URL)
	if err != nil {
		return err
	}
	apiKeyInput, err := m.read("通信密钥 API Key", cfg.Panel.APIKey)
	if err != nil {
		return err
	}
	defaultTarget := cfg.Binding.VPSID
	if defaultTarget == "" {
		defaultTarget = cfg.Binding.NodeID
	}
	targetInput, err := m.read("VPS ID 或 节点 Node ID (UUID)", defaultTarget)
	if err != nil {
		return err
	}
	bindMode, err := m.read("ID 类型 (1=VPS ID / 2=节点 Node ID)", "1")
	if err != nil {
		return err
	}
	cfg.Panel.URL = strings.TrimRight(strings.TrimSpace(urlInput), "/")
	cfg.Panel.APIKey = strings.TrimSpace(apiKeyInput)
	targetInput = strings.TrimSpace(targetInput)
	if bindMode == "2" {
		cfg.Binding.NodeID = targetInput
		cfg.Binding.VPSID = ""
		cfg.Binding.Instances = nil
	} else {
		cfg.Binding.VPSID = targetInput
		cfg.Binding.NodeID = ""
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("配置校验未通过: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(agentconfig.DefaultFile), 0750); err != nil {
		return err
	}
	tmp := agentconfig.DefaultFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0640); err != nil {
		return err
	}
	if u, e := user.Lookup("lineops-agent"); e == nil {
		if gid, e := strconv.Atoi(u.Gid); e == nil {
			_ = os.Chown(filepath.Dir(agentconfig.DefaultFile), 0, gid)
			_ = os.Chown(tmp, 0, gid)
		}
	}
	if err := os.Rename(tmp, agentconfig.DefaultFile); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Remove(filepath.Join(cfg.Paths.AgentStateDir, "identity.json"))
	_ = os.Remove(filepath.Join(cfg.Paths.AgentStateDir, "enrollment-pending.json"))
	fmt.Println("已写入", agentconfig.DefaultFile)
	if m.confirm("是否立即重启 lineops-agent 服务以连接面板") {
		return run("systemctl", "restart", "lineops-agent.service")
	}
	return nil
}

func (m *menu) agentService() error {
	choice, err := m.read("1 启动 / 2 停止 / 3 重启 / 4 开机自启 / 5 取消自启 / 0 返回", "0")
	if err != nil {
		return err
	}
	operation := map[string]string{"1": "start", "2": "stop", "3": "restart", "4": "enable", "5": "disable"}[choice]
	if operation == "" {
		return nil
	}
	return m.controlAgent(operation)
}

func (m *menu) controlAgent(operation string) error {
	if operation != "start" && operation != "stop" && operation != "restart" && operation != "enable" && operation != "disable" {
		return errors.New("不支持的服务操作")
	}
	fmt.Println("仅操作 lineops-agent 服务；不删除身份、不修改 sing-box 配置。停止后面板收不到心跳，也无法下发任务。开机自启设置不改变当前运行状态。")
	if !m.confirm("执行 Agent 服务操作：" + operation) {
		return nil
	}
	if err := run("systemctl", operation, "lineops-agent.service"); err != nil {
		return err
	}
	if operation == "enable" || operation == "disable" {
		return run("systemctl", "show", "lineops-agent.service", "--property=UnitFileState", "--no-pager")
	}
	return run("systemctl", "show", "lineops-agent.service", "--property=ActiveState", "--property=SubState", "--no-pager")
}
