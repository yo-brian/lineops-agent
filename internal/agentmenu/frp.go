package agentmenu

import (
	"context"
	"errors"
	"fmt"
	"lineops-agent/internal/agentproto"
	"lineops-agent/internal/release"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func (m *menu) frpMenu() error {
	st := release.ObserveFRP(m.paths)
	fmt.Println("\n── FRP 内网穿透状态 ──")
	fmt.Printf("  二进制安装: %v (版本: %s)\n", st.Installed, fallbackStr(st.Version, "未安装"))
	fmt.Printf("  服务端 (frps): 启用=%v, 状态=%s, 监听端口=%d\n", st.ServerEnabled, st.ServerState, st.ServerBindPort)
	fmt.Printf("  客户端 (frpc): 启用=%v, 状态=%s, 远端=%s:%d, 映射规则=%d 条\n", st.ClientEnabled, st.ClientState, fallbackStr(st.ClientServerAddr, "—"), st.ClientServerPort, st.ProxyCount)
	choice, err := m.read("1 配置并启动 FRP 服务端 (frps, 公网VPS用) / 2 配置并启动 FRP 客户端 (frpc, 内网Mac/家宽用) / 3 重启 FRP / 4 查看日志 / 5 卸载清理 FRP / 0 返回", "0")
	if err != nil || choice == "0" || choice == "" {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	switch choice {
	case "1":
		portStr, err := m.read("请输入 frps 监听端口", "7000")
		if err != nil {
			return err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return errors.New("端口须为 1–65535")
		}
		defaultToken := agentproto.Token()[:24]
		token, err := m.read("请输入或确认连接密钥 Token", defaultToken)
		if err != nil {
			return err
		}
		req := release.FRPRequest{
			TaskID:         agentproto.ID(),
			Kind:           "configure_frp",
			Fencing:        uint64(time.Now().Unix()),
			ServerEnabled:  true,
			ServerBindPort: port,
			ServerToken:    token,
		}
		fmt.Println("正在检查/下载 FRP 并配置启动 frps 服务端...")
		res := release.ApplyFRP(ctx, m.paths, req)
		if res.State != "succeeded" {
			return fmt.Errorf("配置失败: %s", res.ErrorCode)
		}
		fmt.Printf("[✓] frps 服务端已启动！监听端口: %d, Token: %s\n", port, token)
		return nil

	case "2":
		addr, err := m.read("请输入公网 VPS 的 IP 或域名 (serverAddr)", st.ClientServerAddr)
		if err != nil {
			return err
		}
		defaultPort := "7000"
		if st.ClientServerPort > 0 {
			defaultPort = strconv.Itoa(st.ClientServerPort)
		}
		portStr, err := m.read("请输入公网 frps 端口 (serverPort)", defaultPort)
		if err != nil {
			return err
		}
		serverPort, err := strconv.Atoi(portStr)
		if err != nil || serverPort < 1 || serverPort > 65535 {
			return errors.New("端口须为 1–65535")
		}
		token, err := m.read("请输入 frps 连接密钥 Token", "")
		if err != nil {
			return err
		}
		var proxies []release.FRPProxy
		for {
			localPortStr, err := m.read("请输入要穿透的本机节点端口 (如 sing-box 端口，直接回车结束添加)", "")
			if err != nil {
				return err
			}
			if strings.TrimSpace(localPortStr) == "" {
				break
			}
			lp, err := strconv.Atoi(localPortStr)
			if err != nil || lp < 1 || lp > 65535 {
				fmt.Println("端口无效，请重新输入")
				continue
			}
			rpStr, err := m.read("请输入映射到公网 VPS 的远程端口", localPortStr)
			if err != nil {
				return err
			}
			rp, err := strconv.Atoi(rpStr)
			if err != nil || rp < 1 || rp > 65535 {
				fmt.Println("端口无效，请重新输入")
				continue
			}
			proto, err := m.read("转发协议 (tcp / udp / tcp+udp)", "tcp+udp")
			if err != nil {
				return err
			}
			proxies = append(proxies, release.FRPProxy{
				Name:       fmt.Sprintf("port-%d", lp),
				Protocol:   proto,
				LocalIP:    "127.0.0.1",
				LocalPort:  lp,
				RemotePort: rp,
			})
		}
		req := release.FRPRequest{
			TaskID:           agentproto.ID(),
			Kind:             "configure_frp",
			Fencing:          uint64(time.Now().Unix()),
			ServerEnabled:    st.ServerEnabled,
			ServerBindPort:   st.ServerBindPort,
			ClientEnabled:    true,
			ClientServerAddr: addr,
			ClientServerPort: serverPort,
			ClientToken:      token,
			ClientProxies:    proxies,
		}
		fmt.Println("正在检查/下载 FRP 并配置启动 frpc 客户端...")
		res := release.ApplyFRP(ctx, m.paths, req)
		if res.State != "succeeded" {
			return fmt.Errorf("配置失败: %s", res.ErrorCode)
		}
		fmt.Printf("[✓] frpc 客户端已启动！已连接 %s:%d (%d 条端口映射)\n", addr, serverPort, len(proxies))
		return nil

	case "3":
		res := release.ApplyFRP(ctx, m.paths, release.FRPRequest{
			TaskID:  agentproto.ID(),
			Kind:    "restart_frp",
			Fencing: uint64(time.Now().Unix()),
		})
		if res.State != "succeeded" {
			return fmt.Errorf("重启失败: %s", res.ErrorCode)
		}
		fmt.Println("[✓] FRP 服务已重启")
		return nil

	case "4":
		role, err := m.read("查看哪个日志 (1: frps / 2: frpc)", "2")
		if err != nil {
			return err
		}
		svc := "frpc"
		if role == "1" {
			svc = "frps"
		}
		if runtime.GOOS == "darwin" {
			return run("tail", "-n", "100", "/var/log/lineops-"+svc+".log")
		}
		return run("journalctl", "-u", "lineops-"+svc+".service", "--since", "30 minutes ago", "-n", "100", "--no-pager")

	case "5":
		if !m.confirm("停止并卸载清理本机 FRP 服务与配置") {
			return nil
		}
		res := release.ApplyFRP(ctx, m.paths, release.FRPRequest{
			TaskID:  agentproto.ID(),
			Kind:    "uninstall_frp",
			Fencing: uint64(time.Now().Unix()),
		})
		if res.State != "succeeded" {
			return fmt.Errorf("卸载失败: %s", res.ErrorCode)
		}
		fmt.Println("[✓] FRP 服务与配置已清理")
		return nil
	default:
		return errors.New("请选择有效的操作序号")
	}
}

func fallbackStr(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
