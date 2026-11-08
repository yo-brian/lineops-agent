package agentmenu

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lineops-agent/internal/agentconfig"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

var uuid = regexp.MustCompile(`^[a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$`)

type menu struct {
	cfg   *agentconfig.Config
	paths agentconfig.Paths
	in    *bufio.Reader
	panel *panelClient
}

func Run() error {
	if runtime.GOOS != "linux" {
		return errors.New("管理菜单仅支持 Linux VPS")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("请在交互式终端运行 lineops-agent menu；后台服务仍需指定 --panel 等参数")
	}
	if os.Geteuid() != 0 {
		return errors.New("请使用 sudo lineops-agent")
	}
	m := &menu{in: bufio.NewReader(os.Stdin)}
	defer func() {
		if m.panel != nil {
			m.panel.http.CloseIdleConnections()
		}
	}()
	for {
		m.printHeader()
		fmt.Println("── 状态与诊断 ──\n1. 一键全面自检 (配置 / 面板通信 / 服务 / 节点协议握手)\n2. 查看本机服务与实例状态\n3. 查看 Agent 实时日志\n4. 查看 sing-box 实时日志\n── 配置与服务控制 ──\n5. 配置面板通信 (config.yml: 网址 / API Key / VPS ID)\n6. Agent 服务管理 (启动 / 停止 / 重启 / 开机自启)\n7. 重启或重新同步 sing-box 实例\n── 系统与维护 ──\n8. BBR 加速设置\n9. 升级、解绑与卸载维护\n0. 退出")
		choice, err := m.read("请选择", "")
		if err != nil {
			return err
		}
		if choice == "0" {
			return nil
		}
		if err = m.action(choice); err != nil {
			fmt.Println("未完成：", clean(err.Error()))
		}
	}
}

func (m *menu) read(label, fallback string) (string, error) {
	fmt.Printf("%s", label)
	if fallback != "" {
		fmt.Printf(" [%s]", clean(fallback))
	}
	fmt.Print(": ")
	s, e := m.in.ReadString('\n')
	if e != nil {
		return "", e
	}
	s = strings.TrimSpace(s)
	if s == "" {
		s = fallback
	}
	return s, nil
}
func (m *menu) ask(label, fallback string) string {
	s, e := m.read(label, fallback)
	if e != nil {
		return ""
	}
	return s
}
func (m *menu) confirm(label string) bool {
	return m.ask(label+"；输入 YES 确认，其他输入取消", "") == "YES"
}
func run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}
func (m *menu) loadConfig() error {
	m.paths = agentconfig.NewPaths()
	if _, e := os.Stat(agentconfig.DefaultFile); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	c, e := agentconfig.Load(agentconfig.DefaultFile)
	if e != nil {
		return e
	}
	m.cfg = &c
	m.paths = c.Paths
	return nil
}
func (m *menu) connect() error {
	if e := m.loadConfig(); e != nil {
		return e
	}
	if m.cfg == nil {
		return errors.New("未找到配置文件 /etc/lineops/config.yml")
	}
	p, e := newClient(m.cfg.Panel.URL, m.cfg.Panel.CAFile)
	if e != nil {
		return e
	}
	b, e := protectedRead(filepath.Join(m.paths.AgentStateDir, "identity.json"))
	if e != nil {
		return e
	}
	var identity struct {
		Token   string `json:"identity_token"`
		AgentID string `json:"agent_id"`
		VPSID   string `json:"vps_id"`
	}
	if e = json.Unmarshal(b, &identity); e != nil {
		return errors.New("本机 Agent 身份文件无效")
	}
	if len(identity.Token) != 43 || !uuid.MatchString(identity.AgentID) || !uuid.MatchString(identity.VPSID) {
		return errors.New("Agent 尚未注册，或身份文件无效")
	}
	if m.cfg != nil {
		if e = m.cfg.CheckIdentity(identity.VPSID); e != nil {
			return e
		}
	}
	p.token = identity.Token
	if m.panel != nil {
		m.panel.http.CloseIdleConnections()
	}
	m.panel = p
	return nil
}
func (m *menu) instance() (string, error) {
	if e := m.loadConfig(); e != nil {
		return "", e
	}
	entries, e := os.ReadDir(m.paths.InstancesDir)
	if e != nil {
		return "", e
	}
	var ids []string
	for _, entry := range entries {
		if entry.IsDir() && uuid.MatchString(entry.Name()) {
			ids = append(ids, entry.Name())
		}
	}
	if len(ids) == 0 {
		return "", errors.New("本机尚无已安装的 sing-box 实例")
	}
	if len(ids) == 1 {
		fmt.Printf("已自动选择唯一实例：%s\n", ids[0])
		return ids[0], nil
	}
	for i, id := range ids {
		fmt.Printf("%d. %s\n", i+1, id)
	}
	n, e := strconv.Atoi(m.ask("选择本机实例序号", "1"))
	if e != nil || n < 1 || n > len(ids) {
		return "", errors.New("未选择有效的本机实例")
	}
	return ids[n-1], nil
}
func (m *menu) impact(id string) (object, error) {
	var v object
	e := m.panel.call("GET", "/instances/"+id+"/impact", nil, &v)
	return v, e
}
func show(v any) { b, _ := json.MarshalIndent(v, "", "  "); fmt.Println(string(b)) }
func (m *menu) submit(method, path string, v object) error {
	var out object
	if e := m.panel.call(method, path, v, &out); e != nil {
		return e
	}
	if task := str(out["task_id"]); task != "" {
		fmt.Println("任务 ID：", task)
	} else {
		show(out)
	}
	fmt.Println("请求已受理，不代表服务器已生效。请使用“查看任务结果”确认；未知结果不要强制改为成功。")
	return nil
}
func (m *menu) recoveryBin() string {
	for _, candidate := range []string{
		m.paths.RecoveryBinary(),
		filepath.Join(m.paths.AgentBinDir, "lineops-agent"),
		"/etc/lineops/bin/lineops-agent",
		"/usr/local/bin/lineops-agent",
	} {
		if candidate != "" {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate
			}
		}
	}
	if exe, err := os.Executable(); err == nil && exe != "" {
		return exe
	}
	return m.paths.RecoveryBinary()
}

func (m *menu) localInstances() []string {
	entries, e := os.ReadDir(m.paths.InstancesDir)
	if e != nil {
		return nil
	}
	var ids []string
	for _, entry := range entries {
		if entry.IsDir() && uuid.MatchString(entry.Name()) {
			ids = append(ids, entry.Name())
		}
	}
	return ids
}

func (m *menu) doctor() error {
	fmt.Println("\n── 开始执行 LineOps 一键全面自检 ──")
	failures := 0
	if err := m.loadConfig(); err != nil {
		fmt.Printf("[1/5] 配置文件 (%s): [✗] 异常 (%s)\n", agentconfig.DefaultFile, clean(err.Error()))
		failures++
	} else if m.cfg == nil {
		fmt.Printf("[1/5] 配置文件 (%s): [✗] 未找到配置文件（可在菜单按 5 配置）\n", agentconfig.DefaultFile)
		failures++
	} else {
		bind := m.cfg.Binding.VPSID
		if bind == "" {
			bind = m.cfg.Binding.NodeID
		}
		fmt.Printf("[1/5] 配置文件 (%s): [✓] 正常 (面板=%s, 绑定=%s)\n", agentconfig.DefaultFile, clean(m.cfg.Panel.URL), clean(bind))
	}

	idFile := filepath.Join(m.paths.AgentStateDir, "identity.json")
	if b, err := protectedRead(idFile); err != nil {
		fmt.Printf("[2/5] Agent 身份凭据 (%s): [✗] 未找到或权限异常 (%s)\n", idFile, clean(err.Error()))
		failures++
	} else {
		var id struct {
			Token   string `json:"identity_token"`
			AgentID string `json:"agent_id"`
			VPSID   string `json:"vps_id"`
		}
		if json.Unmarshal(b, &id) != nil || len(id.Token) != 43 || !uuid.MatchString(id.AgentID) || !uuid.MatchString(id.VPSID) {
			fmt.Printf("[2/5] Agent 身份凭据: [✗] 凭据内容格式无效\n")
			failures++
		} else if m.cfg != nil && m.cfg.CheckIdentity(id.VPSID) != nil {
			fmt.Printf("[2/5] Agent 身份凭据: [✗] 凭据 VPS ID (%s) 与 config.yml 绑定不一致\n", clean(id.VPSID))
			failures++
		} else {
			fmt.Printf("[2/5] Agent 身份凭据: [✓] 正常 (AgentID=%s, VPSID=%s)\n", clean(id.AgentID), clean(id.VPSID))
		}
	}

	if err := m.connect(); err != nil {
		fmt.Printf("[3/5] 面板 HTTPS 通信与鉴权: [✗] 无法建立连接 (%s)\n", clean(err.Error()))
		failures++
	} else {
		var list object
		if err := m.panel.call("GET", "/groups?page=1&page_size=1", nil, &list); err != nil {
			fmt.Printf("[3/5] 面板 HTTPS 通信与鉴权: [✗] 面板请求失败 (%s)\n", clean(err.Error()))
			failures++
		} else {
			fmt.Printf("[3/5] 面板 HTTPS 通信与鉴权: [✓] 正常 (HTTPS 握手与 Bearer 凭据验证通过)\n")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	activeOut, activeErr := exec.CommandContext(ctx, "systemctl", "is-active", "lineops-agent.service").Output()
	enabledOut, _ := exec.CommandContext(ctx, "systemctl", "is-enabled", "lineops-agent.service").Output()
	cancel()
	activeState := strings.TrimSpace(string(activeOut))
	enabledState := strings.TrimSpace(string(enabledOut))
	if activeErr != nil || activeState != "active" {
		fmt.Printf("[4/5] Agent 系统服务 (lineops-agent.service): [✗] 未运行 (状态=%s, 自启=%s)\n", clean(activeState), clean(enabledState))
		failures++
	} else {
		fmt.Printf("[4/5] Agent 系统服务 (lineops-agent.service): [✓] 运行中 (状态=%s, 自启=%s)\n", clean(activeState), clean(enabledState))
	}

	ids := m.localInstances()
	if len(ids) == 0 {
		fmt.Printf("[5/5] sing-box 实例与协议探针: [!] 本机尚无已安装的 sing-box 实例 (%s)\n", m.paths.InstancesDir)
	} else {
		bin := m.recoveryBin()
		for _, id := range ids {
			unit := "lineops-sing-box-" + id + ".service"
			sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
			sOut, sErr := exec.CommandContext(sctx, "systemctl", "is-active", unit).Output()
			scancel()
			sState := strings.TrimSpace(string(sOut))
			if sErr != nil || sState != "active" {
				fmt.Printf("[5/5] sing-box 实例 (%s): [✗] 服务未运行 (%s=%s)\n", id, unit, clean(sState))
				failures++
				continue
			}
			vctx, vcancel := context.WithTimeout(context.Background(), 30*time.Second)
			vOut, vErr := exec.CommandContext(vctx, bin, "verify", "--root", m.paths.InstancesDir, "--instance", id).CombinedOutput()
			vcancel()
			if vErr != nil {
				fmt.Printf("[5/5] sing-box 实例 (%s): [✗] 协议或配置核实未通过 (%s: %s)\n", id, clean(vErr.Error()), clean(strings.TrimSpace(string(vOut))))
				failures++
			} else {
				fmt.Printf("[5/5] sing-box 实例 (%s): [✓] 服务运行中，配置签名与节点协议握手全部通过\n", id)
			}
		}
	}

	if failures == 0 {
		fmt.Println("================ 自检完成：全部核心功能正常 ================")
		return nil
	}
	fmt.Printf("================ 自检完成：发现 %d 项异常，请按上方提示处理 ================\n", failures)
	return nil
}

func (m *menu) restartSingboxInstance() error {
	if e := m.loadConfig(); e != nil {
		return e
	}
	id, err := m.instance()
	if err != nil {
		return err
	}
	if err := m.connect(); err != nil {
		if m.confirm("面板暂不可达，是否直接通过本机 systemd 重启 lineops-sing-box-" + id + ".service") {
			return run("systemctl", "restart", "lineops-sing-box-"+id+".service")
		}
		return err
	}
	impact, err := m.impact(id)
	if err != nil {
		return err
	}
	showImpact(impact)
	if !m.confirm("重启此实例：该实例下所有专线组的节点连接都会短暂中断；保留当前配置") {
		return nil
	}
	return m.submit("POST", "/instances/"+id+"/restart", object{"version": impact["version"]})
}

func (m *menu) singboxMenu() error {
	choice, err := m.read("1 重启 sing-box 实例 / 2 重新发布面板当前配置 / 3 校验本机协议并同步未知发布结果 / 0 返回", "0")
	if err != nil || choice == "0" || choice == "" {
		return err
	}
	switch choice {
	case "1":
		return m.restartSingboxInstance()
	case "2":
		if e := m.connect(); e != nil {
			return e
		}
		id, e := m.instance()
		if e != nil {
			return e
		}
		impact, e := m.impact(id)
		if e != nil {
			return e
		}
		showImpact(impact)
		if !m.confirm("按面板当前配置发布整个实例；会保留其他有效节点，可能短暂影响共享实例连接") {
			return nil
		}
		return m.submit("POST", "/instances/"+id+"/publish", object{"version": impact["version"]})
	case "3":
		id, e := m.instance()
		if e != nil {
			return e
		}
		fmt.Println("检查文件、授权和实际协议健康，不修改配置。")
		if e = run(m.recoveryBin(), "verify", "--root", m.paths.InstancesDir, "--instance", id); e != nil {
			return fmt.Errorf("本机核实未通过，请保留日志并检查配置差异：%w", e)
		}
		if !m.confirm("本机检查通过，是否通知面板核实未知发布结果") {
			return nil
		}
		if e = m.connect(); e != nil {
			return e
		}
		v, e := m.impact(id)
		if e != nil {
			return e
		}
		return m.submit("POST", "/instances/"+id+"/reconcile", object{"version": v["version"]})
	default:
		return errors.New("请选择有效的操作序号")
	}
}

func (m *menu) printInstallGuide() {
	fmt.Println("── 统一目录规范 (/etc/lineops) ──")
	fmt.Println("  配置文件: /etc/lineops/config.yml")
	fmt.Println("  程序目录: /etc/lineops/bin/lineops-agent (单二进制集成)")
	fmt.Println("  节点实例: /etc/lineops/instances/<instance_id>/config.json")
	fmt.Println("  运行内核: /etc/lineops/sing-box")
	fmt.Println("  状态目录: /etc/lineops/state/agent, /etc/lineops/state/lifecycle")
	fmt.Println("── 从 GitHub 拉取安装 / 升级 ──")
	fmt.Println("  升级或迁移命令: curl -fsSL https://github.com/yo-brian/lineops-agent/releases/latest/download/install.sh | sudo bash -s -- --upgrade")
	fmt.Println("  强制清理重装:   curl -fsSL https://github.com/yo-brian/lineops-agent/releases/latest/download/install.sh | sudo bash -s -- --clean")
}

func (m *menu) maintainMenu() error {
	choice, err := m.read("1 查看目录规范与升级/重装命令 / 2 解除面板绑定（保留节点） / 0 返回", "0")
	if err != nil || choice == "0" || choice == "" {
		return err
	}
	switch choice {
	case "1":
		m.printInstallGuide()
		return nil
	case "2":
		return m.unbindPanel()
	default:
		return errors.New("请选择有效的操作序号")
	}
}

func (m *menu) action(choice string) error {
	if e := m.loadConfig(); e != nil && choice != "5" && choice != "16" && choice != "config" && choice != "1" && choice != "doctor" {
		return e
	}
	switch choice {
	case "1", "doctor":
		return m.doctor()
	case "2", "status":
		_ = run("systemctl", "status", "lineops-agent", "lineops-sing-box-*", "--no-pager", "-l")
		ids := m.localInstances()
		if len(ids) == 0 {
			return nil
		}
		id := ids[0]
		if len(ids) > 1 {
			var err error
			id, err = m.instance()
			if err != nil {
				return err
			}
		}
		fmt.Printf("\n── 实例 %s 本机保存状态 ──\n", id)
		if e := run(m.recoveryBin(), "status", "--root", m.paths.InstancesDir, "--instance", id); e != nil {
			return e
		}
		if !m.confirm("是否连接面板查看该实例节点列表") {
			return nil
		}
		if e := m.connect(); e != nil {
			return e
		}
		v, e := m.impact(id)
		if e != nil {
			return e
		}
		showImpact(v)
		return nil
	case "3", "log":
		return run("journalctl", "-u", "lineops-agent", "--since", "30 minutes ago", "-n", "100", "--no-pager")
	case "4", "singbox-log":
		id, err := m.instance()
		if err != nil {
			return err
		}
		return run("journalctl", "-u", "lineops-sing-box-"+id+".service", "--since", "30 minutes ago", "-n", "100", "--no-pager")
	case "5", "16", "config":
		return m.configureConfigYML()
	case "6":
		return m.agentService()
	case "7":
		return m.singboxMenu()
	case "8":
		return m.bbr()
	case "9":
		return m.maintainMenu()
	case "11", "singbox-restart":
		return m.restartSingboxInstance()
	case "14":
		m.printInstallGuide()
		return nil
	case "15", "unbind":
		return m.unbindPanel()
	default:
		return errors.New("请选择菜单中的序号 (0-9)")
	}
}

// BBR changes are deliberately runtime-only: no vendor sysctl file is overwritten.
func (m *menu) bbr() error {
	if e := run("sysctl", "net.ipv4.tcp_available_congestion_control", "net.ipv4.tcp_congestion_control", "net.core.default_qdisc"); e != nil {
		return e
	}
	fmt.Println("设置仅本次开机有效，重启后按系统原配置恢复；不保证线路提速。首次修改会备份当前值。")
	choice := m.ask("1 启用 BBR / 2 恢复本菜单修改前的设置 / 其他返回", "")
	if choice != "1" && choice != "2" {
		return nil
	}
	if !m.confirm("修改本机 TCP 拥塞控制设置") {
		return nil
	}
	return setBBR(choice == "1")
}
