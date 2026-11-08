#!/usr/bin/env bash
# LineOps Agent (Single-Binary / Single-Service) Unified Installer & Upgrader
# Standard root directory: /etc/lineops
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

PANEL_URL=""
API_KEY=""
VPS_ID=""
NODE_ID=""
FORCE_CLEAN=0
RELEASE_URL="${LINEOPS_AGENT_RELEASE_URL:-https://github.com/yo-brian/lineops-agent/releases/latest/download}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) PANEL_URL="$2"; shift 2 ;;
    --api-key) API_KEY="$2"; shift 2 ;;
    --vps-id) VPS_ID="$2"; shift 2 ;;
    --node-id) NODE_ID="$2"; shift 2 ;;
    --clean|--reinstall) FORCE_CLEAN=1; shift ;;
    *) shift ;;
  esac
done

TMP_DIR=$(mktemp -d /tmp/lineops-agent-install.XXXXXXXX)
cleanup() {
  rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT

# Ensure standard /etc/lineops directory hierarchy exists
install -d -m 0755 -o root -g root \
  /etc/lineops \
  /etc/lineops/bin \
  /etc/lineops/sing-box \
  /etc/lineops/state \
  /etc/lineops/backups
install -d -m 0711 -o root -g root /etc/lineops/instances
install -d -m 0700 -o root -g root \
  /etc/lineops/state/agent \
  /etc/lineops/state/lifecycle \
  /etc/lineops/backups/agent-upgrades
for owned_dir in /etc/lineops /etc/lineops/bin /etc/lineops/state/agent; do
  printf 'lineops-agent-v1\n' > "$owned_dir/.lineops-owned"
  chmod 0600 "$owned_dir/.lineops-owned"
done

# Optional explicit --clean reset
if [[ "$FORCE_CLEAN" -eq 1 ]]; then
  echo "Cleaning LineOps state and resetting /etc/lineops ..."
  systemctl stop lineops-agent.service >/dev/null 2>&1 || true

  for unit_file in \
    /etc/systemd/system/lineops-sing-box-*.service \
    /etc/systemd/system/lineops-policy-*.service \
    /etc/systemd/system/lineops-policy-*.timer \
    /etc/systemd/system/lineops-singbox@*.service; do
    [[ -e "$unit_file" || -L "$unit_file" ]] || continue
    unit_name=$(basename "$unit_file")
    systemctl disable --now "$unit_name" >/dev/null 2>&1 || true
    rm -f "$unit_file"
  done

  rm -rf /etc/lineops/instances/* /etc/lineops/sing-box/* /etc/lineops/state/lifecycle/* /etc/lineops/state/agent/*
  for owned_dir in /etc/lineops /etc/lineops/bin /etc/lineops/state/agent; do
    printf 'lineops-agent-v1\n' > "$owned_dir/.lineops-owned"
    chmod 0600 "$owned_dir/.lineops-owned"
  done
  echo "Clean reset under /etc/lineops complete."
else
  echo "Updating LineOps Agent under /etc/lineops (preserving config.yml and sing-box instances)."
fi

if ! getent passwd lineops-singbox >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin lineops-singbox || true
fi

# Resolve or download latest lineops-agent binary from GitHub Releases
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" 2>/dev/null && pwd -P || pwd -P)
BIN_SRC=""
for candidate in \
  "$SCRIPT_DIR/lineops-agent-linux-$ARCH" \
  "$SCRIPT_DIR/../bin/lineops-agent-linux-$ARCH"; do
  if [[ -f "$candidate" ]]; then
    BIN_SRC="$candidate"
    break
  fi
done

if [[ -z "$BIN_SRC" ]]; then
  TMP_BIN="$TMP_DIR/lineops-agent-linux-$ARCH"
  echo "Downloading lineops-agent-linux-$ARCH from $RELEASE_URL ..."
  if ! curl --fail --location --show-error --connect-timeout 15 --max-time 600 --retry 4 --retry-delay 2 \
    "$RELEASE_URL/lineops-agent-linux-$ARCH" -o "$TMP_BIN"; then
    echo "Error: Failed to download lineops-agent-linux-$ARCH from $RELEASE_URL" >&2
    exit 1
  fi
  if curl --fail --silent --location --connect-timeout 10 --max-time 30 --retry 3 --retry-delay 2 \
    "$RELEASE_URL/SHA256SUMS" -o "$TMP_DIR/SHA256SUMS" 2>/dev/null; then
    expected_hash=$(awk -v f="lineops-agent-linux-$ARCH" '$2 == f || $2 == "*"f {print $1}' "$TMP_DIR/SHA256SUMS" | head -n 1)
    if [[ -n "$expected_hash" ]]; then
      actual_hash=$(sha256sum "$TMP_BIN" | awk '{print $1}')
      if [[ "${actual_hash,,}" != "${expected_hash,,}" ]]; then
        echo "Error: SHA256 checksum mismatch for lineops-agent-linux-$ARCH" >&2
        exit 1
      fi
      echo "SHA256 checksum verified: $actual_hash"
    fi
  fi
  BIN_SRC="$TMP_BIN"
fi

# Remove old Agent binary first, then install fresh binary into /etc/lineops/bin
systemctl stop lineops-agent.service >/dev/null 2>&1 || true
rm -f /etc/lineops/bin/lineops-agent /etc/lineops/bin/lineops-recovery
install -m 0755 -o root -g root "$BIN_SRC" /etc/lineops/bin/lineops-agent
ln -f /etc/lineops/bin/lineops-agent /etc/lineops/bin/lineops-recovery
ln -sf /etc/lineops/bin/lineops-agent /usr/local/bin/lineops-agent

# Install or download lineops-singbox binary into /etc/lineops/bin/lineops-singbox if not present
for sb in "$SCRIPT_DIR/lineops-singbox-linux-$ARCH" "$SCRIPT_DIR/lineops-singbox" "$SCRIPT_DIR/sing-box"; do
  if [[ -f "$sb" ]]; then
    install -m 0755 -o root -g root "$sb" /etc/lineops/bin/lineops-singbox
    break
  fi
done

if [[ ! -f /etc/lineops/bin/lineops-singbox ]]; then
  TMP_SB="$TMP_DIR/lineops-singbox-linux-$ARCH"
  if curl --fail --silent --location --connect-timeout 15 --max-time 600 --retry 2 \
    "$RELEASE_URL/lineops-singbox-linux-$ARCH" -o "$TMP_SB" 2>/dev/null; then
    install -m 0755 -o root -g root "$TMP_SB" /etc/lineops/bin/lineops-singbox
    echo "Downloaded lineops-singbox-linux-$ARCH into /etc/lineops/bin/lineops-singbox"
  fi
fi

# Create or update /etc/lineops/config.yml
if [[ -n "$PANEL_URL" || -n "$API_KEY" || -n "$VPS_ID" || -n "$NODE_ID" ]]; then
  # Preserve existing values from /etc/lineops/config.yml for any flag not explicitly provided
  if [[ -f /etc/lineops/config.yml ]]; then
    [[ -n "$PANEL_URL" ]] || PANEL_URL=$(grep -E '^\s*url:' /etc/lineops/config.yml | head -n 1 | sed -E 's/^\s*url:\s*"?([^"#]+)"?.*/\1/' | xargs || true)
    [[ -n "$API_KEY" ]] || API_KEY=$(grep -E '^\s*api_key:' /etc/lineops/config.yml | head -n 1 | sed -E 's/^\s*api_key:\s*"?([^"#]+)"?.*/\1/' | xargs || true)
    [[ -n "$VPS_ID" ]] || VPS_ID=$(grep -E '^\s*vps_id:' /etc/lineops/config.yml | head -n 1 | sed -E 's/^\s*vps_id:\s*"?([^"#]+)"?.*/\1/' | xargs || true)
    [[ -n "$NODE_ID" ]] || NODE_ID=$(grep -E '^\s*node_id:' /etc/lineops/config.yml | head -n 1 | sed -E 's/^\s*node_id:\s*"?([^"#]+)"?.*/\1/' | xargs || true)
  fi
  cat > /etc/lineops/config.yml <<YAML
schema_version: 1
panel:
  url: "${PANEL_URL:-https://panel.example.com}"
  api_key: "${API_KEY}"

binding:
  vps_id: "${VPS_ID}"
  node_id: "${NODE_ID}"
YAML
  chmod 0600 /etc/lineops/config.yml
  chown root:root /etc/lineops/config.yml
  echo "Configuration written to /etc/lineops/config.yml"
elif [[ ! -f /etc/lineops/config.yml ]]; then
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

if grep -qE 'api_key:\s*"?[A-Za-z0-9_-]{20,}' /etc/lineops/config.yml 2>/dev/null; then
  systemctl restart lineops-agent.service
  echo "Started lineops-agent.service"
fi

echo "========================================================"
echo "LineOps Agent installed in /etc/lineops!"
echo "1. Edit /etc/lineops/config.yml or run: sudo lineops-agent config"
echo "2. Start/Restart service:              sudo systemctl restart lineops-agent"
echo "3. Open interactive management menu:   sudo lineops-agent"
echo "========================================================"
