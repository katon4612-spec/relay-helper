#!/usr/bin/env bash
# 旧「限时代理网关」(Docker 版 socks-gateway) → s-ui + 中转助手，一条命令迁移，客户链接不变。
# 在旧网关服务器上用 root 运行：
#   bash <(curl -fsSL https://raw.githubusercontent.com/katon4612-spec/relay-helper/main/migrate_gateway.sh)
# 旧网关不在 /opt/socks-gateway 时，把目录加在命令最后。
set -u
GW_DIR="${1:-/opt/socks-gateway}"
RAW="https://raw.githubusercontent.com/katon4612-spec/relay-helper/main"
EXPORT=/root/gateway-export.json
LOG=/root/migrate-$(date +%Y%m%d-%H%M%S).log
RH=/opt/relay-helper

[ "$(id -u)" = "0" ] || { echo "请用 root 运行"; exit 1; }
exec > >(tee -a "$LOG") 2>&1
step() { echo; echo "========== $* =========="; }
fail() { echo; echo "✗ $*"; echo "（完整过程记录在 $LOG，发给我看就行）"; exit 1; }
ask() { local a; read -r -p "$1" a < /dev/tty || a=""; echo "$a"; }
dc() { (cd "$GW_DIR" && { docker compose "$@" 2>/dev/null || docker-compose "$@"; }); }

[ -d "$GW_DIR" ] || fail "没找到旧网关目录 $GW_DIR（旧网关装在别的目录的话，把目录加在命令最后）"
command -v python3 >/dev/null || { apt-get update -y && apt-get install -y python3; } >/dev/null 2>&1 || yum install -y python3 >/dev/null 2>&1
command -v python3 >/dev/null || fail "装不上 python3"

# ---------------------------------------------------------------- 1 导出
step "1/6 导出旧网关正在使用的客户"
RUNNING=$(dc ps -q gateway 2>/dev/null | head -1)
if [ -z "$RUNNING" ] && [ -f "$EXPORT" ]; then
  echo "旧网关已经停了，使用之前导出的 $EXPORT"
else
  curl -fsSL "$RAW/gateway_export.py" -o /root/gateway_export.py || fail "下载导出脚本失败（这台机器连不上 GitHub？）"
  python3 /root/gateway_export.py "$GW_DIR" || fail "导出失败"
fi
read -r N HOST <<<"$(python3 -c '
import json;b=json.load(open("'"$EXPORT"'"))
print(len(b["customers"]), b.get("public_host") or b.get("admin_domain") or "-")')"
[ "$N" -gt 0 ] 2>/dev/null || fail "导出文件里没有正在使用的客户"
if [ "$HOST" = "-" ]; then
  HOST=$(ask "没读到客户链接里的域名，请输入（例如 skzf.liveshop.work）: ")
fi
echo
echo "将迁移 $N 个客户，客户链接里的域名：$HOST"
echo "接下来会：停掉旧网关 → 安装 s-ui 和中转助手 → 原样导入客户。客户会断开几分钟。"
[ "$(ask "确认开始？输入 y 回车: ")" = "y" ] || { echo "已取消，什么都没改。"; exit 0; }

# ---------------------------------------------------------------- 2 停旧网关
step "2/6 停掉旧网关（数据保留，随时可以恢复）"
dc down || fail "停旧网关失败"
sleep 2

# ---------------------------------------------------------------- 3 s-ui
step "3/6 安装 s-ui"
SUI_NEW=0
if systemctl list-unit-files 2>/dev/null | grep -q '^s-ui\.service'; then
  echo "s-ui 已经装了，跳过"
else
  VERSION=v1.3.10
  echo n | bash <(curl -Ls "https://raw.githubusercontent.com/alireza0/s-ui/$VERSION/install.sh") $VERSION || fail "安装 s-ui 失败"
  SUI_NEW=1
fi
SUI_BIN=/usr/local/s-ui/sui
SUI_USER=""; SUI_PASS=""
if [ "$SUI_NEW" = "1" ] && [ -x "$SUI_BIN" ]; then
  SUI_USER="admin$(tr -dc a-z0-9 </dev/urandom | head -c 4)"
  SUI_PASS="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)"
  (cd /usr/local/s-ui && "$SUI_BIN" admin -username "$SUI_USER" -password "$SUI_PASS") >/dev/null || fail "设置 s-ui 账号失败"
  systemctl restart s-ui
fi
for i in $(seq 1 20); do systemctl is-active --quiet s-ui && break; sleep 1; done
systemctl is-active --quiet s-ui || fail "s-ui 没有启动起来"

# ---------------------------------------------------------------- 4 中转助手
step "4/6 安装中转助手"
RH_PUBLIC_HOST="$HOST" bash <(curl -fsSL "$RAW/install.sh") </dev/null || fail "安装中转助手失败"
# 访问路径统一成 /kaide/
python3 - <<PY
import json;p="$RH/config.json";d=json.load(open(p));d["path"]="/kaide/";json.dump(d,open(p,"w"),ensure_ascii=False,indent=2)
PY
systemctl restart relay-helper
for i in $(seq 1 30); do
  python3 -c "import json,sys;sys.exit(0 if json.load(open('$RH/config.json')).get('api_token') else 1)" 2>/dev/null && break; sleep 1
done
sleep 3

# ---------------------------------------------------------------- 5 导入
step "5/6 导入客户（原端口、原密码、原 Reality 密钥）"
python3 - "$EXPORT" <<'PY' || fail "导入失败"
import json, ssl, sys, time, urllib.request
cfg = json.load(open("/opt/relay-helper/config.json"))
scheme = "https" if cfg.get("cert_file") else "http"
base = "%s://127.0.0.1:%s%sapi/" % (scheme, cfg["port"], cfg["path"])
ctx = ssl._create_unverified_context()
def api(a, body=None):
    req = urllib.request.Request(base + a, data=json.dumps(body or {}).encode(),
                                 headers={"Content-Type": "application/json", "X-RH-Token": cfg["api_token"]})
    for i in range(10):
        try:
            with urllib.request.urlopen(req, timeout=120, context=ctx) as r:
                d = json.loads(r.read().decode())
            if not d.get("ok", True):
                raise RuntimeError(d.get("error"))
            return d
        except RuntimeError:
            raise
        except Exception as e:
            if i == 9:
                raise
            time.sleep(3)
src = {"path": sys.argv[1]}
c = api("gateway_check", src)
print("要导入 %d 个客户，%d 个落地；端口被占用 %d 个" % (c["total"], c["landings"], c["n_conflicts"]))
for x in c["conflicts"][:10]:
    print("  占用：%s 端口 %s" % (x["username"], x["port"]))
api("gateway_import", src)
while True:
    time.sleep(3)
    s = api("gateway_status")
    if s["running"]:
        print("  进度 %d/%d" % (s["done"], s["total"]))
        continue
    if s["error"]:
        raise SystemExit("导入出错：" + s["error"])
    print("✓ 导入完成：成功 %d 个，失败 %d 个" % (s["imported"], len(s["failed"])))
    for f in s["failed"]:
        print("  失败：%s（%s 端口 %s）：%s" % (f["username"], f["protocol"], f["port"], f.get("error")))
    break
PY

# ---------------------------------------------------------------- 6 完成
step "6/6 完成"
PORT=$(python3 -c "import json;print(json.load(open('$RH/config.json'))['port'])")
MODE=$(python3 -c "import json;print(json.load(open('$RH/config.json')).get('https_mode','http'))")
SCH=https; [ "$MODE" = "http" ] && SCH=http
echo "中转助手：$SCH://$HOST:$PORT/kaide/"
if [ -n "$SUI_USER" ]; then
  echo "登录账号：$SUI_USER"
  echo "登录密码：$SUI_PASS"
  echo "（中转助手和 s-ui 面板 http://$HOST:2095/app/ 都用这个账号密码，请记下来，以后可以在 s-ui 里改）"
else
  echo "登录账号密码：和这台 s-ui 面板的一样"
fi
[ "$MODE" = "selfsigned" ] && echo "⚠ 证书是自签名的（80 端口没放行或域名没解析到本机），浏览器会提示不安全；订阅链接小火箭拉不了。放行 TCP 80 后运行：bash $RH/https.sh $RH force && systemctl restart relay-helper"
echo
echo "请马上拿一个客户的旧链接连一下确认。没问题的话："
echo "  1. 删除导出文件（里面有客户密码）：rm $EXPORT"
echo "  2. 云服务商安全组再放行 TCP 2095、2097 和新建节点用的端口（10000-60000 TCP+UDP）"
echo "  3. 到主控 bgp02 的「服务器」页把这台加进去（连接密钥在这台中转助手的「服务器」页）"
echo
echo "万一有问题要退回旧网关：systemctl stop s-ui && cd $GW_DIR && docker compose up -d"
echo "完整过程记录：$LOG"
