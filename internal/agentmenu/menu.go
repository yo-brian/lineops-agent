package agentmenu

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lineops-agent/internal/agentconfig"
	"net/url"
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
		fmt.Println("── 快速配置与状态 ──\n16. 配置面板通信 (config.yml：网址 / API Key / 节点 ID)\n1. 查看本机服务状态\n8. 查看 Agent 实时日志\n12. 查看 sing-box 日志\n2. 查看本机实例与节点\n7. 检查服务器实际状态\n10. 查看任务结果\n── 节点与服务管理 ──\n3. 新增节点\n4. 编辑节点\n5. 删除指定节点\n6. 发布面板当前配置\n11. 重启 sing-box 实例\n13. Agent 服务管理（启动／停止／重启／自启）\n── 系统维护 ──\n9. BBR 加速设置\n14. 安装、升级与卸载说明\n15. 解除面板绑定（保留节点）\n0. 退出")
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
		if _, legErr := os.Stat("/opt/lineops-agent"); legErr == nil {
			m.paths = agentconfig.LegacyPaths()
		}
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
	settings := map[string]string{}
	var b []byte
	var e error
	if m.cfg != nil {
		settings["LINEOPS_PANEL"] = m.cfg.Panel.URL
		settings["LINEOPS_CA_FILE"] = m.cfg.Panel.CAFile
	} else {
		b, e = protectedRead("/etc/lineops-agent/agent.env")
		if e != nil {
			return e
		}
		for _, line := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if ok {
				settings[k] = strings.TrimSpace(v)
			}
		}
	}
	p, e := newClient(settings["LINEOPS_PANEL"], settings["LINEOPS_CA_FILE"])
	if e != nil {
		return e
	}
	b, e = protectedRead(filepath.Join(m.paths.AgentStateDir, "identity.json"))
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
func (m *menu) action(choice string) error {
	if e := m.loadConfig(); e != nil {
		return e
	}
	switch choice {
	case "1":
		return run("systemctl", "status", "lineops-agent", "lineops-sing-box-*", "--no-pager", "-l")
	case "8":
		return run("journalctl", "-u", "lineops-agent", "--since", "30 minutes ago", "-n", "100", "--no-pager")
	case "9":
		return m.bbr()
	case "12":
		id, err := m.instance()
		if err != nil {
			return err
		}
		return run("journalctl", "-u", "lineops-sing-box-"+id+".service", "--since", "30 minutes ago", "-n", "100", "--no-pager")
	case "13":
		return m.agentService()
	case "15":
		return m.unbindPanel()
	case "16", "config":
		return m.configureConfigYML()
	case "14":
		fmt.Println("── 统一目录规范 (/etc/lineops) ──")
		fmt.Println("  配置文件: /etc/lineops/config.yml")
		fmt.Println("  程序目录: /etc/lineops/bin (lineops-agent, lineops-singbox)")
		fmt.Println("  节点实例: /etc/lineops/instances/<instance_id>/config.json")
		fmt.Println("  运行内核: /etc/lineops/sing-box")
		fmt.Println("  状态目录: /etc/lineops/state/agent, /etc/lineops/state/lifecycle")
		fmt.Println("── 从 GitHub 拉取安装 / 升级 ──")
		fmt.Println("  升级或迁移命令: curl -fsSL https://github.com/yo-brian/lineops-agent/releases/latest/download/install.sh | sudo bash -s -- --upgrade")
		fmt.Println("  强制清理重装:   curl -fsSL https://github.com/yo-brian/lineops-agent/releases/latest/download/install.sh | sudo bash -s -- --clean")
		return nil
	case "2", "3", "4", "5", "6", "7", "10", "11":
	default:
		return errors.New("请选择菜单中的序号")
	}
	if choice == "2" {
		id, e := m.instance()
		if e != nil {
			return e
		}
		fmt.Println("本机保存的最近状态（不代表刚刚通过健康检查）：")
		if e = run(m.paths.RecoveryBinary(), "status", "--root", m.paths.InstancesDir, "--instance", id); e != nil {
			return e
		}
		if !m.confirm("是否连接面板查看该实例节点列表") {
			return nil
		}
		if e = m.connect(); e != nil {
			return e
		}
		v, e := m.impact(id)
		if e != nil {
			return e
		}
		showImpact(v)
		return nil
	}
	if choice == "7" {
		id, e := m.instance()
		if e != nil {
			return e
		}
		fmt.Println("检查文件、授权和实际协议健康，不修改配置。配置被手动修改时会拒绝核实；此菜单不会绕过校验。")
		if e = run(m.paths.RecoveryBinary(), "verify", "--root", m.paths.InstancesDir, "--instance", id); e != nil {
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
	}
	if e := m.connect(); e != nil {
		return e
	}
	if choice == "10" {
		id := m.ask("任务 ID", "")
		if !uuid.MatchString(id) {
			return errors.New("任务 ID 无效")
		}
		var v object
		if e := m.panel.call("GET", "/tasks/"+id, nil, &v); e != nil {
			return e
		}
		showTask(v)
		return nil
	}
	id, e := m.instance()
	if e != nil {
		return e
	}
	impact, e := m.impact(id)
	if e != nil {
		return e
	}
	if choice == "11" {
		showImpact(impact)
		if !m.confirm("重启此实例：该实例下所有专线组的节点连接都会短暂中断；保留当前配置") {
			return nil
		}
		return m.submit("POST", "/instances/"+id+"/restart", object{"version": impact["version"]})
	}
	if choice == "6" {
		showImpact(impact)
		if !m.confirm("按面板当前配置发布整个实例；会保留其他有效节点，可能短暂影响共享实例连接") {
			return nil
		}
		return m.submit("POST", "/instances/"+id+"/publish", object{"version": impact["version"]})
	}
	if choice == "3" {
		return m.create(id, impact)
	}
	return m.change(id, impact, choice == "5")
}

func (m *menu) change(instance string, impact object, deleting bool) error {
	var nodes []object
	if items, ok := impact["nodes"].([]any); ok {
		for _, item := range items {
			if v, ok := item.(map[string]any); ok {
				nodes = append(nodes, v)
				fmt.Printf("%d. %s 端口 %v 状态 %s/%s\n", len(nodes), str(v["name"]), v["port"], str(v["desired_state"]), str(v["actual_state"]))
			}
		}
	}
	n, e := strconv.Atoi(m.ask("选择节点序号", ""))
	if e != nil || n < 1 || n > len(nodes) {
		return errors.New("节点选择无效")
	}
	node := nodes[n-1]
	id := str(node["id"])
	group := str(node["group_id"])
	if !uuid.MatchString(id) || !uuid.MatchString(group) {
		return errors.New("节点数据无效")
	}
	nodes, e = m.panel.nodes(group)
	if e != nil {
		return e
	}
	var current object
	for _, v := range nodes {
		if str(v["id"]) == id && str(v["instance_id"]) == instance {
			current = v
		}
	}
	if current == nil {
		return errors.New("节点已变化，请刷新")
	}
	if str(current["desired_state"]) == "deleted" {
		return errors.New("节点已进入删除流程，请检查任务结果或核实服务器状态；不能重复删除或强制清理")
	}
	if deleting {
		if !m.confirm("删除节点 " + str(current["name"]) + "（" + id + "），其他节点保留；共享实例应用配置可能短暂影响连接") {
			return nil
		}
		return m.submit("POST", "/nodes/"+id+"/state", object{"version": current["version"], "state": "deleted"})
	}
	v := object{"version": current["version"], "name": m.ask("节点名称", str(current["name"])), "access_address": m.ask("客户端接入域名或 IP", str(current["access_address"]))}
	if m.confirm("是否同时编辑监听端口及传输参数") {
		var detail struct {
			Config  object  `json:"config"`
			Version float64 `json:"version"`
		}
		if e = m.panel.call("GET", "/nodes/"+id+"/configuration", nil, &detail); e != nil {
			return e
		}
		if detail.Version != current["version"] {
			return errors.New("节点已变化，请重新选择")
		}
		config := detail.Config
		if str(config["relay_source_node"]) != "" || str(config["relay_address"]) != "" {
			return errors.New("中转节点请在面板编辑依赖关系")
		}
		port, e := strconv.Atoi(m.ask("监听端口", str(config["port"])))
		if e != nil {
			return e
		}
		config["port"] = port
		config["listen"] = m.ask("监听 IP", str(config["listen"]))
		if str(config["security"]) != "none" {
			config["server_name"] = m.ask("TLS/Reality 服务器名", str(config["server_name"]))
		}
		if str(config["transport"]) == "ws" {
			config["transport_path"] = m.ask("WebSocket 路径", str(config["transport_path"]))
		}
		if str(config["transport"]) == "grpc" {
			config["grpc_service_name"] = m.ask("gRPC 服务名", str(config["grpc_service_name"]))
		}
		v["config"] = config
	}
	if !m.confirm("保存节点 " + str(v["name"]) + " 并同步策略") {
		return nil
	}
	return m.submit("PUT", "/nodes/"+id, v)
}

func (m *menu) create(id string, impact object) error {
	fmt.Println("新增直连节点，密钥由面板生成。请选择所属专线组：")
	group, err := m.chooseGroup()
	if err != nil {
		return err
	}
	var dep object
	if e := m.panel.call("GET", "/groups/"+group+"/deployment", nil, &dep); e != nil {
		return e
	}
	name := m.ask("节点名称", "")
	address := m.ask("客户端接入域名或 IP", "")
	port, e := strconv.Atoi(m.ask("监听端口（1024–65535）", ""))
	if e != nil {
		return e
	}
	v := object{"version": dep["version"], "instance_id": id, "instance_version": impact["version"], "deploy": true, "name": name, "access_address": address, "listen": "0.0.0.0", "port": port, "transport": "tcp"}
	protocolChoice := m.ask("协议：1 Shadowsocks / 2 VLESS Reality / 3 VLESS TLS / 4 Trojan TLS", "2")
	switch protocolChoice {
	case "1":
		v["protocol"] = "shadowsocks"
		v["security"] = "none"
		v["method"] = m.ask("加密方式", "2022-blake3-aes-128-gcm")
	case "2":
		v["protocol"] = "vless"
		v["security"] = "reality"
		v["flow"] = "xtls-rprx-vision"
		v["server_name"] = m.ask("Reality 服务器名", "")
		v["reality_handshake"] = v["server_name"]
		v["reality_handshake_port"] = 443
	case "3", "4":
		v["protocol"] = "vless"
		if protocolChoice == "4" {
			v["protocol"] = "trojan"
		}
		v["security"] = "tls"
		v["server_name"] = m.ask("TLS 服务器名", address)
		cert := m.ask("面板证书 ID", "")
		if !uuid.MatchString(cert) {
			return errors.New("证书 ID 无效")
		}
		v["certificate_id"] = cert
	default:
		return errors.New("协议选择无效")
	}
	show(v)
	if !m.confirm("将节点保存到面板并发布整个实例；其他有效节点保留") {
		return nil
	}
	return m.submit("POST", "/groups/"+group+"/nodes", v)
}

func (m *menu) chooseGroup() (string, error) {
	query, e := m.read("搜索本 VPS 已关联的专线组（回车查看全部）", "")
	if e != nil {
		return "", e
	}
	page := 1
	for {
		var list struct {
			Items []object `json:"items"`
			Total int      `json:"total"`
		}
		path := fmt.Sprintf("/groups?page_size=20&page=%d&q=%s", page, url.QueryEscape(query))
		if e = m.panel.call("GET", path, nil, &list); e != nil {
			return "", e
		}
		for i, v := range list.Items {
			fmt.Printf("%d. %s\n", i+1, str(v["name"]))
		}
		fmt.Printf("第 %d 页，共 %d 个专线组\n", page, list.Total)
		choice, e := m.read("序号 / n 下一页 / p 上一页 / 0 取消（也可粘贴专线组 ID）", "")
		if e != nil {
			return "", e
		}
		if choice == "0" {
			return "", errors.New("已取消")
		}
		if choice == "n" {
			if page*20 < list.Total {
				page++
			}
			continue
		}
		if choice == "p" {
			if page > 1 {
				page--
			}
			continue
		}
		if uuid.MatchString(choice) {
			return choice, nil
		}
		n, e := strconv.Atoi(choice)
		if e == nil && n > 0 && n <= len(list.Items) {
			id := str(list.Items[n-1]["id"])
			if uuid.MatchString(id) {
				return id, nil
			}
		}
		fmt.Println("请选择有效的专线组。")
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
