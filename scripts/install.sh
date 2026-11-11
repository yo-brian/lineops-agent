#!/usr/bin/env bash
# LineOps Agent (Single-Binary / Single-Service) Unified Installer & Upgrader (Linux & macOS)
# Standard root directory: /etc/lineops
set -Eeuo pipefail

if [[ $(id -u) != 0 ]]; then
  echo "Error: Please run this installer as root (sudo bash install.sh)" >&2
  exit 1
fi

OS_NAME=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS_NAME" in
  linux)
    OS_NAME="linux"
    ROOT_GROUP="root"
    ;;
  darwin)
    OS_NAME="darwin"
    ROOT_GROUP="wheel"
    ;;
  *)
    echo "Unsupported operating system: $OS_NAME" >&2
    exit 1
    ;;
esac

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

PANEL_URL=""
API_KEY=""
VPS_ID=""
NODE_ID=""
FORCE_CLEAN=0
UPGRADE=0
RELEASE_URL="${LINEOPS_AGENT_RELEASE_URL:-https://github.com/yo-brian/lineops-agent/releases/latest/download}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) PANEL_URL="$2"; shift 2 ;;
    --api-key) API_KEY="$2"; shift 2 ;;
    --vps-id) VPS_ID="$2"; shift 2 ;;
    --node-id) NODE_ID="$2"; shift 2 ;;
    --clean|--reinstall) FORCE_CLEAN=1; shift ;;
    --upgrade) UPGRADE=1; shift ;;
    *) shift ;;
  esac
done

TMP_DIR=$(mktemp -d /tmp/lineops-agent-install.XXXXXXXX)
cleanup() {
  rm -rf -- "$TMP_DIR"
  if [[ "$OS_NAME" == "linux" ]] && [[ -x /etc/lineops/bin/lineops-agent ]] && [[ -f /etc/systemd/system/lineops-agent.service ]]; then
    if grep -qE 'api_key:\s*"?[A-Za-z0-9_-]{20,}' /etc/lineops/config.yml 2>/dev/null || [[ -f /etc/lineops/state/agent/credentials.json ]]; then
      systemctl is-active --quiet lineops-agent.service || systemctl start lineops-agent.service >/dev/null 2>&1 || true
    fi
  fi
}
trap cleanup EXIT

# Ensure standard /etc/lineops directory hierarchy exists
install -d -m 0755 -o root -g "$ROOT_GROUP" \
  /etc/lineops \
  /etc/lineops/bin \
  /etc/lineops/sing-box \
  /etc/lineops/frp \
  /etc/lineops/state \
  /etc/lineops/backups \
  /usr/local/bin
install -d -m 0711 -o root -g "$ROOT_GROUP" /etc/lineops/instances
install -d -m 0700 -o root -g "$ROOT_GROUP" \
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
  if [[ "$OS_NAME" == "darwin" ]]; then
    /bin/launchctl bootout system /Library/LaunchDaemons/com.lineops.agent.plist >/dev/null 2>&1 || true
    for plist_file in /Library/LaunchDaemons/com.lineops.sing-box.*.plist /Library/LaunchDaemons/com.lineops.frps.plist /Library/LaunchDaemons/com.lineops.frpc.plist; do
      [[ -e "$plist_file" ]] || continue
      /bin/launchctl bootout system "$plist_file" >/dev/null 2>&1 || true
      rm -f "$plist_file"
    done
  else
    systemctl stop lineops-agent.service >/dev/null 2>&1 || true
    for unit_file in \
      /etc/systemd/system/lineops-sing-box-*.service \
      /etc/systemd/system/lineops-frps.service \
      /etc/systemd/system/lineops-frpc.service \
      /etc/systemd/system/lineops-policy-*.service \
      /etc/systemd/system/lineops-policy-*.timer \
      /etc/systemd/system/lineops-singbox@*.service; do
      [[ -e "$unit_file" || -L "$unit_file" ]] || continue
      unit_name=$(basename "$unit_file")
      systemctl disable --now "$unit_name" >/dev/null 2>&1 || true
      rm -f "$unit_file"
    done
  fi

  rm -rf /etc/lineops/instances/* /etc/lineops/sing-box/* /etc/lineops/frp/* /etc/lineops/state/lifecycle/* /etc/lineops/state/agent/*
  for owned_dir in /etc/lineops /etc/lineops/bin /etc/lineops/state/agent; do
    printf 'lineops-agent-v1\n' > "$owned_dir/.lineops-owned"
    chmod 0600 "$owned_dir/.lineops-owned"
  done
  echo "Clean reset under /etc/lineops complete."
else
  echo "Updating LineOps Agent under /etc/lineops (preserving config.yml and sing-box instances)."
fi

if [[ "$OS_NAME" == "linux" ]]; then
  if ! getent passwd lineops-singbox >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin lineops-singbox || true
  fi
fi

# Resolve or download latest lineops-agent binary from GitHub Releases
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" 2>/dev/null && pwd -P || pwd -P)
BIN_NAME="lineops-agent-${OS_NAME}-${ARCH}"
BIN_SRC=""
for candidate in \
  "$SCRIPT_DIR/$BIN_NAME" \
  "$SCRIPT_DIR/../bin/$BIN_NAME"; do
  if [[ -f "$candidate" ]]; then
    BIN_SRC="$candidate"
    break
  fi
done

if [[ -z "$BIN_SRC" ]]; then
  TMP_BIN="$TMP_DIR/$BIN_NAME"
  echo "Downloading $BIN_NAME from $RELEASE_URL ..."
  if ! curl --fail --location --show-error --connect-timeout 15 --max-time 600 --retry 4 --retry-delay 2 \
    "$RELEASE_URL/$BIN_NAME" -o "$TMP_BIN"; then
    echo "Error: Failed to download $BIN_NAME from $RELEASE_URL" >&2
    exit 1
  fi
  if curl --fail --silent --location --connect-timeout 10 --max-time 30 --retry 3 --retry-delay 2 \
    "$RELEASE_URL/SHA256SUMS" -o "$TMP_DIR/SHA256SUMS" 2>/dev/null; then
    expected_hash=$(awk -v f="$BIN_NAME" '$2 == f || $2 == "*"f {print $1}' "$TMP_DIR/SHA256SUMS" | head -n 1)
    if [[ -n "$expected_hash" ]]; then
      actual_hash=$(sha256_file "$TMP_BIN")
      if [[ "$(echo "$actual_hash" | tr '[:upper:]' '[:lower:]')" != "$(echo "$expected_hash" | tr '[:upper:]' '[:lower:]')" ]]; then
        echo "Error: SHA256 checksum mismatch for $BIN_NAME" >&2
        exit 1
      fi
      echo "SHA256 checksum verified: $actual_hash"
    fi
  fi
  BIN_SRC="$TMP_BIN"
fi

# Stop existing Agent service, then install fresh binary into /etc/lineops/bin
if [[ "$OS_NAME" == "darwin" ]]; then
  /bin/launchctl bootout system /Library/LaunchDaemons/com.lineops.agent.plist >/dev/null 2>&1 || true
else
  systemctl stop lineops-agent.service >/dev/null 2>&1 || true
fi
rm -f /etc/lineops/bin/lineops-agent /etc/lineops/bin/lineops-recovery
install -m 0755 -o root -g "$ROOT_GROUP" "$BIN_SRC" /etc/lineops/bin/lineops-agent
ln -f /etc/lineops/bin/lineops-agent /etc/lineops/bin/lineops-recovery
ln -sf /etc/lineops/bin/lineops-agent /usr/local/bin/lineops-agent

# Install or download lineops-singbox binary into /etc/lineops/bin/lineops-singbox
SB_NAME="lineops-singbox-${OS_NAME}-${ARCH}"
for sb in "$SCRIPT_DIR/$SB_NAME" "$SCRIPT_DIR/lineops-singbox" "$SCRIPT_DIR/sing-box" "/opt/homebrew/bin/sing-box"; do
  if [[ -f "$sb" ]]; then
    install -m 0755 -o root -g "$ROOT_GROUP" "$sb" /etc/lineops/bin/lineops-singbox
    break
  fi
done

if [[ ! -f /etc/lineops/bin/lineops-singbox || "$UPGRADE" -eq 1 ]]; then
  TMP_SB="$TMP_DIR/$SB_NAME"
  if curl --fail --silent --location --connect-timeout 15 --max-time 600 --retry 2 \
    "$RELEASE_URL/$SB_NAME" -o "$TMP_SB" 2>/dev/null; then
    install -m 0755 -o root -g "$ROOT_GROUP" "$TMP_SB" /etc/lineops/bin/lineops-singbox
    echo "Downloaded $SB_NAME into /etc/lineops/bin/lineops-singbox"
  fi
fi

# Create or update /etc/lineops/config.yml
if [[ -n "$PANEL_URL" || -n "$API_KEY" || -n "$VPS_ID" || -n "$NODE_ID" ]]; then
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
  chown root:"$ROOT_GROUP" /etc/lineops/config.yml
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
  chown root:"$ROOT_GROUP" /etc/lineops/config.yml
  echo "Created default configuration at /etc/lineops/config.yml"
fi

if [[ "$OS_NAME" == "darwin" ]]; then
  cat > /Library/LaunchDaemons/com.lineops.agent.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.lineops.agent</string>
	<key>ProgramArguments</key>
	<array>
		<string>/etc/lineops/bin/lineops-agent</string>
		<string>--config</string>
		<string>/etc/lineops/config.yml</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>/var/log/lineops-agent.log</string>
	<key>StandardErrorPath</key>
	<string>/var/log/lineops-agent.log</string>
</dict>
</plist>
PLIST
  chmod 0644 /Library/LaunchDaemons/com.lineops.agent.plist
  chown root:wheel /Library/LaunchDaemons/com.lineops.agent.plist
  if grep -qE 'api_key:\s*"?[A-Za-z0-9_-]{20,}' /etc/lineops/config.yml 2>/dev/null || [[ -f /etc/lineops/state/agent/identity.json ]]; then
    /bin/launchctl bootstrap system /Library/LaunchDaemons/com.lineops.agent.plist >/dev/null 2>&1 || /bin/launchctl load -w /Library/LaunchDaemons/com.lineops.agent.plist >/dev/null 2>&1 || true
    /bin/launchctl kickstart -k system/com.lineops.agent >/dev/null 2>&1 || true
    echo "Started com.lineops.agent (macOS launchd)"
  fi
else
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

  if grep -qE 'api_key:\s*"?[A-Za-z0-9_-]{20,}' /etc/lineops/config.yml 2>/dev/null || [[ -f /etc/lineops/state/agent/credentials.json ]]; then
    systemctl restart lineops-agent.service
    echo "Started lineops-agent.service"
  fi
fi

echo "========================================================"
echo "LineOps Agent (${OS_NAME}-${ARCH}) installed in /etc/lineops!"
echo "1. Configure: sudo lineops-agent config"
echo "2. Restart:   sudo lineops-agent restart"
echo "3. Menu:      sudo lineops-agent"
echo "========================================================"
