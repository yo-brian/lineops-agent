#!/usr/bin/env bash
# LineOps Agent (Single-Binary / Single-Service) Installer
set -Eeuo pipefail

if [[ $(id -u) != 0 ]]; then
  echo "Error: Please run this installer as root (sudo bash install.sh)" >&2
  exit 1
fi

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
BIN_SRC=""
for candidate in \
  "$SCRIPT_DIR/lineops-agent-linux-$ARCH" \
  "$SCRIPT_DIR/../bin/lineops-agent-linux-$ARCH" \
  "$SCRIPT_DIR/lineops-agent"; do
  if [[ -f "$candidate" ]]; then
    BIN_SRC="$candidate"
    break
  fi
done

if [[ -z "$BIN_SRC" ]]; then
  echo "Error: Binary lineops-agent-linux-$ARCH not found next to install.sh or in ../bin/" >&2
  exit 1
fi

# Stop legacy split services if migrating from old multi-service setup
for legacy_unit in lineops-executor.service lineops-recovery.timer lineops-recovery.service; do
  if systemctl list-unit-files "$legacy_unit" >/dev/null 2>&1; then
    systemctl disable --now "$legacy_unit" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$legacy_unit"
  fi
done

# Create standard directory layout
install -d -m 0755 -o root -g root /etc/lineops /etc/lineops/bin /var/lib/lineops /var/lib/lineops/singbox
install -d -m 0711 -o root -g root /var/lib/lineops/instances
install -d -m 0700 -o root -g root /var/lib/lineops/agent /var/lib/lineops/upgrades /var/lib/lineops/lifecycle

if ! getent passwd lineops-singbox >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin lineops-singbox || true
fi

# Install single binary and recovery hardlink + CLI symlink
install -m 0755 -o root -g root "$BIN_SRC" /etc/lineops/bin/lineops-agent
ln -f /etc/lineops/bin/lineops-agent /etc/lineops/bin/lineops-recovery
ln -sf /etc/lineops/bin/lineops-agent /usr/local/bin/lineops-agent

# Install bundled sing-box binary if present alongside installer
for sb in "$SCRIPT_DIR/lineops-singbox-linux-$ARCH" "$SCRIPT_DIR/lineops-singbox" "$SCRIPT_DIR/sing-box"; do
  if [[ -f "$sb" ]]; then
    install -m 0755 -o root -g root "$sb" /etc/lineops/bin/lineops-singbox
    break
  fi
done

# Create default /etc/lineops/config.yml if not present
if [[ ! -f /etc/lineops/config.yml ]]; then
  cat > /etc/lineops/config.yml <<'YAML'
schema_version: 1
panel:
  url: https://panel.example.com
  # 长期通信密钥（在面板 VPS 详情 -> Agent 管理 -> config.yml 直连配置中获取）
  api_key: ""

binding:
  # 填写 VPS ID 或该 VPS 下任意一个节点的 Node ID 即可自动完成接管与节点同步
  vps_id: ""
  node_id: ""
YAML
  chmod 0600 /etc/lineops/config.yml
  chown root:root /etc/lineops/config.yml
  echo "Created default configuration at /etc/lineops/config.yml"
fi

# Install single systemd service
cat > /etc/systemd/system/lineops-agent.service <<'UNIT'
[Unit]
Description=LineOps Agent (All-in-One Node Daemon)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
UMask=0077
ExecStart=/etc/lineops/bin/lineops-agent --config /etc/lineops/config.yml
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable lineops-agent.service

echo "========================================================"
echo "LineOps Agent installed successfully!"
echo "1. Edit /etc/lineops/config.yml or run: sudo lineops-agent config"
echo "2. Start/Restart service:              sudo systemctl restart lineops-agent"
echo "3. Open interactive management menu:   sudo lineops-agent"
echo "========================================================"
