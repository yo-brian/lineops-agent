# lineops-agent

`lineops-agent` 是从 LineOps 面板独立出来的 **单二进制、单服务** 节点端程序（定位类似 `xboard-node`）。

## 核心特性

1. **单二进制 + 单服务极简架构（方案 B）**
   - 将原有的 `lineops-agent`、`lineops-executor`、`lineops-recovery` 合并为 **1 个二进制文件** (`/etc/lineops/bin/lineops-agent`) 和 **1 个 systemd 服务** (`lineops-agent.service`)。
   - 彻底剥离面板端的 PostgreSQL (`pgx`)、Web 框架 (`gin`)、TOTP/Bcrypt 等依赖。
2. **`/etc/lineops/config.yml` 直连通信（换机免“重建并接管”）**
   - 只需在 `/etc/lineops/config.yml` 中配置 `panel.url`、`panel.api_key` 以及 `binding.vps_id`（或 `binding.node_id`）。
   - 更换 VPS 时，把同一份 `config.yml` 放到新机器启动即可自动吊销旧机器凭据、自动安装 `sing-box` 并自动下发所有节点配置。
3. **双端日志查看与终端快捷管理**
   - 随心跳自动采集 `lineops-agent` 与各 `sing-box` 实例的最新 `journalctl` 日志上报至面板。
   - 在 VPS 终端执行 `sudo lineops-agent` 即可进入交互菜单，或使用快捷命令：
     - `sudo lineops-agent config`：交互式设置面板网址、`api_key`、`vps_id` / `node_id` 并重启生效
     - `sudo lineops-agent status`：查看 Agent 与 `sing-box` 运行状态
     - `sudo lineops-agent log`：查看 Agent 实时日志
     - `sudo lineops-agent singbox-log`：查看 `sing-box` 实例日志（单实例自动选中）
     - `sudo lineops-agent singbox-restart`：重启 `sing-box` 实例

---

## 目录结构

```text
lineops-agent/
├── cmd/agent/             # 单二进制入口（内置守护进程、CLI 交互菜单、本地执行引擎与恢复子命令）
├── internal/
│   ├── agent/             # 面板心跳、API Key 自动注册、日志采集、命令拉取
│   ├── agentbridge/       # 进程内 (In-Process) 与兼容 Unix Socket 的本地执行桥接
│   ├── agentconfig/       # /etc/lineops/config.yml 解析与严格校验
│   ├── agentmenu/         # VPS 终端交互式菜单与快捷命令
│   ├── agentproto/        # 与面板通信的轻量协议定义
│   ├── release/           # sing-box 配置渲染、生命周期管理、探针与流量统计
│   └── traffic/           # 流量采样模型
├── deploy/
│   ├── config.yml.example # 配置文件模板
│   └── lineops-agent.service
└── scripts/
    ├── build.ps1          # Windows 下交叉编译 linux-amd64 / linux-arm64
    ├── build.sh           # Linux/macOS 下交叉编译脚本
    └── install.sh         # VPS 一键安装 / 升级脚本
```

---

## 编译与安装

### 1. 编译 Linux 二进制

在 Windows PowerShell 下：
```powershell
.\scripts\build.ps1
```

在 Linux / macOS 下：
```bash
bash scripts/build.sh
```
生成产物位于 `bin/lineops-agent-linux-amd64` 与 `bin/lineops-agent-linux-arm64`。

### 2. 在 VPS 上安装

将编译好的二进制与 `scripts/install.sh` 上传至 VPS 后执行：
```bash
sudo bash install.sh
```

随后编辑 `/etc/lineops/config.yml`（或运行 `sudo lineops-agent config`）：
```yaml
schema_version: 1
panel:
  url: https://your-panel.example.com
  api_key: "<面板生成的长期通信 API Key>"

binding:
  # 二选一：填 VPS ID 或该 VPS 下任意一个节点的 Node ID
  vps_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  node_id: ""
```

重启服务即可自动完成注册与节点同步：
```bash
sudo systemctl restart lineops-agent
```
