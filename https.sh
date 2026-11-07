#!/usr/bin/env bash
# 给中转助手页面配置 HTTPS（由 install.sh 调用，也可单独运行：bash https.sh /opt/relay-helper [force]）
#   1) 已有证书（含沿用 s-ui 面板证书）→ 不动
#   2) 地址是域名且 80 端口空闲 → acme.sh 申请 Let's Encrypt 证书，自动续签（续签后重启中转助手）
#   3) 申请失败 / 地址是 IP / 80 端口被占 → 自签名证书（同样加密，浏览器首次打开要点「继续访问」）
DIR="${1:-/opt/relay-helper}"
FORCE="$2"
CFG="$DIR/config.json"
CERT_DIR="$DIR/cert"
ACME="$HOME/.acme.sh/acme.sh"

cfg_get() { python3 -c "import json,sys;print(json.load(open('$CFG',encoding='utf-8-sig')).get('$1','') or '')"; }
cfg_set() { python3 - "$CFG" "$@" <<'PY'
import json, os, sys
p = sys.argv[1]; c = json.load(open(p, encoding="utf-8-sig"))
for kv in sys.argv[2:]:
    k, _, v = kv.partition("=")
    c[k] = (v == "true") if v in ("true", "false") else v
tmp = p + ".tmp"; json.dump(c, open(tmp, "w", encoding="utf-8"), ensure_ascii=False, indent=2); os.chmod(tmp, 0o600); os.replace(tmp, p)
PY
}

HOST="$(cfg_get public_host)"
CUR="$(cfg_get cert_file)"
if [ -z "$FORCE" ] && [ -n "$CUR" ] && [ -f "$CUR" ]; then echo "HTTPS 已启用（$CUR）"; exit 0; fi
if [ -z "$FORCE" ] && [ "$(cfg_get https_declined)" = "True" ]; then echo "已选择不启用 HTTPS（重新启用：bash $DIR/https.sh $DIR force）"; exit 0; fi

if [ -t 0 ] && [ -z "$RH_HTTPS_YES" ]; then
  read -r -p "为中转助手页面启用 HTTPS（推荐，登录密码和落地账号加密传输）？[Y/n] " ans
  case "$ans" in n|N|no|NO) cfg_set https_declined=true; echo "跳过 HTTPS"; exit 0;; esac
fi
mkdir -p "$CERT_DIR"; chmod 700 "$CERT_DIR"

is_ip() { python3 -c "import ipaddress,sys;ipaddress.ip_address(sys.argv[1].strip('[]'))" "$1" 2>/dev/null; }

issue_le() {
  is_ip "$HOST" && { echo "地址是 IP，Let's Encrypt 不签发，改用自签名证书"; return 1; }
  if command -v ss >/dev/null 2>&1 && ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE '(^|:)80$'; then
    echo "80 端口已被占用，无法自动申请证书，改用自签名证书"; return 1
  fi
  command -v socat >/dev/null 2>&1 || (apt-get install -y socat >/dev/null 2>&1 || yum install -y socat >/dev/null 2>&1 || dnf install -y socat >/dev/null 2>&1)
  if [ ! -x "$ACME" ]; then
    echo "安装 acme.sh ..."
    curl -fsSL https://get.acme.sh | sh >/dev/null 2>&1 || wget -qO- https://get.acme.sh | sh >/dev/null 2>&1
  fi
  [ -x "$ACME" ] || { echo "acme.sh 安装失败"; return 1; }
  OPENED=""
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then ufw allow 80/tcp >/dev/null && OPENED=ufw; fi
  echo "向 Let's Encrypt 申请 $HOST 的证书（需要 $HOST 解析到本机，且云安全组放行 TCP 80）..."
  "$ACME" --issue -d "$HOST" --standalone --server letsencrypt --keylength ec-256 >/tmp/relay-helper-acme.log 2>&1
  rc=$?
  [ "$OPENED" = ufw ] && ufw delete allow 80/tcp >/dev/null 2>&1
  if [ $rc -ne 0 ] && [ $rc -ne 2 ]; then   # 2 = 证书已存在且未到续签时间
    echo "申请失败（详细日志 /tmp/relay-helper-acme.log），改用自签名证书"; return 1
  fi
  "$ACME" --install-cert -d "$HOST" --ecc --key-file "$CERT_DIR/key.pem" --fullchain-file "$CERT_DIR/cert.pem" \
    --reloadcmd "systemctl restart relay-helper" >/dev/null 2>&1 || return 1
  [ -s "$CERT_DIR/cert.pem" ] && [ -s "$CERT_DIR/key.pem" ] || return 1
  cfg_set "cert_file=$CERT_DIR/cert.pem" "key_file=$CERT_DIR/key.pem" https_mode=letsencrypt https_declined=false
  echo "✓ 已申请 Let's Encrypt 证书，到期前会自动续签"
}

self_signed() {
  command -v openssl >/dev/null 2>&1 || (apt-get install -y openssl >/dev/null 2>&1 || yum install -y openssl >/dev/null 2>&1)
  if is_ip "$HOST"; then SAN="IP:$HOST"; else SAN="DNS:$HOST"; fi
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=$HOST" -addext "subjectAltName=$SAN" \
    -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" >/dev/null 2>&1 || \
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=$HOST" -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" >/dev/null 2>&1
  [ -s "$CERT_DIR/cert.pem" ] || { echo "生成自签名证书失败，继续使用 HTTP"; return 1; }
  chmod 600 "$CERT_DIR/key.pem"
  cfg_set "cert_file=$CERT_DIR/cert.pem" "key_file=$CERT_DIR/key.pem" https_mode=selfsigned https_declined=false
  echo "✓ 已启用 HTTPS（自签名证书：浏览器第一次打开会提示不安全，点「高级 → 继续访问」即可，传输同样是加密的）"
}

# s-ui 面板已经配了这个域名的证书：直接沿用（不用再申请，不用开 80 端口；s-ui 那边续签后中转助手会自动换上新证书）
use_sui_cert() {
  is_ip "$HOST" && return 1
  local out
  out="$(python3 - "$CFG" "$HOST" <<'PY'
import json, sqlite3, ssl, sys, os, time
cfg = json.load(open(sys.argv[1], encoding="utf-8-sig")); host = sys.argv[2]
db = cfg.get("sui_db") or "/usr/local/s-ui/db/s-ui.db"
try:
    c = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    st = {k: (v.decode() if isinstance(v, bytes) else v) for k, v in c.execute("select key, value from settings")}
except Exception:
    sys.exit(1)
cert, key = st.get("webCertFile") or "", st.get("webKeyFile") or ""
if not (cert and key and os.path.isfile(cert) and os.path.isfile(key)):
    sys.exit(1)
try:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
    info = ssl._ssl._test_decode_cert(cert)
except Exception:
    sys.exit(1)
names = [v for k, v in info.get("subjectAltName", ()) if k == "DNS"]
ok_name = any(n == host or (n.startswith("*.") and host.endswith(n[1:]) and host.count(".") == n.count(".")) for n in names)
if not ok_name or ssl.cert_time_to_seconds(info["notAfter"]) < time.time():
    sys.exit(1)
print(cert + "|" + key)
PY
)" || return 1
  cfg_set "cert_file=${out%%|*}" "key_file=${out##*|}" https_mode=sui https_declined=false
  echo "✓ 已沿用 s-ui 面板的证书（${out%%|*}），和 s-ui 一样显示安全"
}

[ -n "$RH_SKIP_LE" ] && { use_sui_cert || self_signed; exit $?; }
use_sui_cert || issue_le || self_signed
