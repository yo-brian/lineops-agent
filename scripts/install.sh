#!/usr/bin/env bash
set -euo pipefail

REPO="${LINEOPS_AGENT_REPO:-yo-brian/lineops-agent}"
VERSION="${LINEOPS_AGENT_VERSION:-latest}"
PANEL_URL=""
API_KEY=""
VPS_ID=""
NODE_ID=""
CLEAN_INSTALL=0
INSTANCES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) PANEL_URL="$2"; shift 2 ;;
    --api-key) API_KEY="$2"; shift 2 ;;
    --token) shift 2 ;;
    --vps-id) VPS_ID="$2"; shift 2 ;;
    --node-id) NODE_ID="$2"; shift 2 ;;
    --instance) INSTANCES+=("$2"); shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --clean) CLEAN_INSTALL=1; shift ;;
    --upgrade) shift ;;
    *) echo "Unknown parameter: $1" >&2; exit 1 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "请使用 root 或 sudo 运行此安装脚本" >&2
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "不支持的 CPU 架构: $ARCH" >&2; exit 1 ;;
esac

if ! id -u lineops-agent >/dev/null 2>&1; then
  useradd --system --home-dir /etc/lineops/state/agent --no-create-home --shell /usr/sbin/nologin lineops-agent
fi

if [[ "$CLEAN_INSTALL" -eq 1 ]]; then
  echo "正在执行清理重装 (--clean)..."
  systemctl disable --now lineops-agent.service 2>/dev/null || true
  for unit in $(systemctl list-unit-files 'lineops-sing-box-*.service' --no-legend 2>/dev/null | awk '{print $1}'); do
    systemctl disable --now "$unit" 2>/dev/null || true
    rm -f "/etc/systemd/system/$unit"
  done
  rm -rf /etc/lineops/state/agent/* /etc/lineops/state/lifecycle/* /etc/lineops/instances/*
  rm -f /etc/lineops/config.yml /etc/lineops/config.yml.tmp
fi

install -d -m 0755 -o root -g root /etc/lineops /etc/lineops/bin /etc/lineops/instances /etc/lineops/state
install -d -m 0750 -o root -g lineops-agent /etc/lineops
install -d -m 0700 -o lineops-agent -g lineops-agent /etc/lineops/state/agent
install -d -m 0700 -o root -g root /etc/lineops/state/lifecycle
printf 'lineops-agent-v1\n' > /etc/lineops/.lineops-owned
chmod 0400 /etc/lineops/.lineops-owned
printf 'lineops-agent-v1\n' > /etc/lineops/state/agent/.lineops-owned
chown lineops-agent:lineops-agent /etc/lineops/state/agent/.lineops-owned
chmod 0400 /etc/lineops/state/agent/.lineops-owned

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

if [[ "$VERSION" == "latest" ]]; then
  DOWNLOAD_BASE="https://github.com/${REPO}/releases/latest/download"
else
  DOWNLOAD_BASE="https://github.com/${REPO}/releases/download/${VERSION}"
fi

echo "正在从 GitHub 下载 LineOps Agent (${ARCH})..."
curl -fsSL --retry 4 --retry-delay 2 "${DOWNLOAD_BASE}/lineops-agent_${ARCH}.tar.gz" -o "${TMP_DIR}/lineops-agent.tar.gz"
tar -xzf "${TMP_DIR}/lineops-agent.tar.gz" -C "${TMP_DIR}"

install -m 0755 -o root -g root "${TMP_DIR}/lineops-agent" /etc/lineops/bin/lineops-agent
ln -f /etc/lineops/bin/lineops-agent /etc/lineops/bin/lineops-recovery
ln -sf /etc/lineops/bin/lineops-agent /usr/local/bin/lineops-agent
ln -sf /etc/lineops/bin/lineops-agent /usr/local/bin/lineops-singbox

if [[ ! -x /etc/lineops/sing-box ]]; then
  if curl -fsSL --retry 4 --retry-delay 2 "${DOWNLOAD_BASE}/lineops-singbox_${ARCH}.tar.gz" -o "${TMP_DIR}/lineops-singbox.tar.gz" 2>/dev/null; then
    mkdir -p "${TMP_DIR}/sb"
    tar -xzf "${TMP_DIR}/lineops-singbox.tar.gz" -C "${TMP_DIR}/sb"
    SB_BIN="$(find "${TMP_DIR}/sb" -type f -name 'sing-box' | head -n 1 || true)"
    if [[ -n "$SB_BIN" ]]; then
      install -m 0755 -o root -g root "$SB_BIN" /etc/lineops/sing-box
    fi
  fi
fi

if [[ -n "$PANEL_URL" || -n "$API_KEY" || -n "$VPS_ID" || -n "$NODE_ID" ]]; then
  if [[ -z "$PANEL_URL" || -z "$API_KEY" || ( -z "$VPS_ID" && -z "$NODE_ID" ) ]]; then
    echo "配置写入失败: 必须同时提供 --url, --api-key 以及 --vps-id (或 --node-id)" >&2
    exit 1
  fi
  cat > /etc/lineops/config.yml.tmp <<EOF
panel:
  url: "${PANEL_URL}"
  api_key: "${API_KEY}"
binding:
EOF
  if [[ -n "$VPS_ID" ]]; then
    echo "  vps_id: \"${VPS_ID}\"" >> /etc/lineops/config.yml.tmp
    if [[ "${#INSTANCES[@]}" -gt 0 ]]; then
      echo "  instances:" >> /etc/lineops/config.yml.tmp
      for inst in "${INSTANCES[@]}"; do
        echo "    - \"${inst}\"" >> /etc/lineops/config.yml.tmp
      done
    fi
  else
    echo "  node_id: \"${NODE_ID}\"" >> /etc/lineops/config.yml.tmp
  fi
  cat >> /etc/lineops/config.yml.tmp <<EOF
paths:
  agent_bin_dir: "/etc/lineops/bin"
  agent_state_dir: "/etc/lineops/state/agent"
  instances_dir: "/etc/lineops/instances"
  singbox_bin: "/etc/lineops/sing-box"
  lifecycle_dir: "/etc/lineops/state/lifecycle"
EOF
  chown root:lineops-agent /etc/lineops/config.yml.tmp
  chmod 0640 /etc/lineops/config.yml.tmp
  mv -f /etc/lineops/config.yml.tmp /etc/lineops/config.yml
  rm -f /etc/lineops/state/agent/identity.json /etc/lineops/state/agent/enrollment-pending.json
  echo "已生成配置文件 /etc/lineops/config.yml"
fi

cat > /etc/systemd/system/lineops-agent.service <<'EOF'
[Unit]
Description=LineOps VPS Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=lineops-agent
Group=lineops-agent
ExecStart=/etc/lineops/bin/lineops-agent --config /etc/lineops/config.yml
Restart=always
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/lineops/state/agent
ReadOnlyPaths=/etc/lineops
SupplementaryGroups=systemd-journal

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/sudoers.d/lineops-agent-executor <<'EOF'
Defaults:lineops-agent !requiretty
lineops-agent ALL=(root) NOPASSWD: /etc/lineops/bin/lineops-agent executor --from-agent
EOF
chmod 0440 /etc/sudoers.d/lineops-agent-executor

systemctl daemon-reload
if [[ -f /etc/lineops/config.yml ]]; then
  systemctl enable --now lineops-agent.service
  systemctl restart lineops-agent.service
  echo "LineOps Agent 已启动并设置为开机自启。"
else
  echo "LineOps Agent 已安装完成。请运行 'sudo lineops-agent config' 或编辑 /etc/lineops/config.yml 配置面板通信后启动服务。"
fi
