#!/usr/bin/env bash
# 中转助手 一键安装 / 升级脚本（在装有 s-ui 的中转服务器上用 root 运行）
#   bash <(curl -fsSL https://raw.githubusercontent.com/katon4612-spec/relay-helper/main/install.sh)   在线安装/升级
#   bash install.sh            安装或升级（升级会保留原配置）
#   bash install.sh uninstall  卸载
set -e
DIR=/opt/relay-helper
SRC="$(cd "$(dirname "$0")" && pwd)"
SVC=/etc/systemd/system/relay-helper.service

[ "$(id -u)" = "0" ] || { echo "请用 root 运行"; exit 1; }

REPO="katon4612-spec/relay-helper"
# 用一行命令在线安装时（bash <(curl ...)），脚本旁边没有程序文件：从 GitHub 下载最新版
if [ ! -f "$SRC/app.py" ] && [ "$1" != "uninstall" ]; then
  TMP="$(mktemp -d)"
  URL="https://github.com/$REPO/archive/refs/heads/main.tar.gz"
  echo "下载最新版 $URL"
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$URL" | tar xz -C "$TMP"
  else wget -qO- "$URL" | tar xz -C "$TMP"; fi
  SRC="$TMP/relay-helper-main"
  [ -f "$SRC/app.py" ] || { echo "下载失败"; exit 1; }
fi

if [ "$1" = "uninstall" ]; then
  systemctl disable --now relay-helper 2>/dev/null || true
  rm -f "$SVC"; systemctl daemon-reload
  rm -rf "$DIR"
  echo "已卸载中转助手（s-ui 里已建的线路不受影响）"
  exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "安装 python3 ..."
  (apt-get update -y && apt-get install -y python3) || yum install -y python3 || dnf install -y python3
fi
if ! command -v iptables >/dev/null 2>&1 || ! command -v iptables-restore >/dev/null 2>&1; then
  echo "安装 iptables（踢出设备、设备数限制要用）..."
  (apt-get update -y && apt-get install -y iptables) || yum install -y iptables || dnf install -y iptables || apk add iptables ip6tables || echo "⚠ iptables 安装失败，踢出设备和设备数限制将不生效"
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)' || { echo "需要 Python 3.7 以上"; exit 1; }
python3 -c 'import sqlite3' || { echo "python3 缺少 sqlite3 模块"; exit 1; }
systemctl list-unit-files 2>/dev/null | grep -q '^s-ui\.service' || echo "⚠ 没找到 s-ui 服务，确认这台机器装了 s-ui"

mkdir -p "$DIR"
if [ "$SRC" != "$DIR" ]; then
  install -m 644 "$SRC/app.py" "$SRC/qrencoder.py" "$SRC/index.html" "$SRC/configure.py" "$DIR/"
  install -m 755 "$SRC/https.sh" "$DIR/"
  install -m 755 "$SRC/install.sh" "$DIR/"
fi

python3 "$DIR/configure.py"
bash "$DIR/https.sh" "$DIR" || true

cat > "$SVC" <<EOF
[Unit]
Description=Relay Helper for s-ui
After=network.target s-ui.service

[Service]
Type=simple
WorkingDirectory=$DIR
ExecStart=$(command -v python3) $DIR/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable relay-helper >/dev/null 2>&1
systemctl restart relay-helper
sleep 2

PORT=$(python3 -c "import json;print(json.load(open('$DIR/config.json'))['port'])")
WPATH=$(python3 -c "import json;print(json.load(open('$DIR/config.json'))['path'])")
PASS=$(python3 -c "import json;print(json.load(open('$DIR/config.json'))['password'])")
HOST=$(python3 -c "import json;print(json.load(open('$DIR/config.json'))['public_host'])")
SCHEME=$(python3 -c "import json;c=json.load(open('$DIR/config.json'));print('https' if c.get('cert_file') else 'http')")

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then ufw allow "$PORT/tcp" >/dev/null; fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
  firewall-cmd --permanent --add-port="$PORT/tcp" >/dev/null && firewall-cmd --reload >/dev/null; fi

if systemctl is-active --quiet relay-helper; then
  echo ""
  echo "=============================================="
  echo " 中转助手已运行"
  echo " 地址： $SCHEME://$HOST:$PORT$WPATH"
  echo " 密码： $PASS"
  echo "----------------------------------------------"
  echo " 云服务器安全组需要放行 TCP $PORT（工具页面）"
  echo " 以及中转端口范围（默认 10000-60000，TCP+UDP）"
  echo " 配置文件：$DIR/config.json   日志：journalctl -u relay-helper -f"
  echo "=============================================="
else
  echo "启动失败，查看日志： journalctl -u relay-helper -n 50"
  exit 1
fi
