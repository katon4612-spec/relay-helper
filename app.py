#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
中转助手 (relay-helper) —— 给 s-ui 面板用的一键中转工具

粘贴落地（socks5 / http / vless / vmess / trojan / hy2 / ss / tuic / anytls 链接，或 IP:端口:账号:密码）
→ 在 s-ui 里自动建好：出站(落地) + 入站(vless-reality / hysteria2 / socks5) + 用户 + 路由规则
→ 输出客户链接和二维码。还支持：检测落地连通、原位替换落地、改到期、停用/启用、删除。

只依赖 Python 3 标准库，通过 s-ui 自带的 API 操作，不直接改数据库。
"""
import base64
import hashlib
import hmac
import http.cookiejar
import ipaddress
import json
import os
import random
import re
import secrets
import shutil
import sqlite3
import ssl
import socket
import string
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import qrencoder  # noqa: E402  (vendored, MIT)

CONFIG_PATH = os.environ.get("RELAY_HELPER_CONFIG", os.path.join(HERE, "config.json"))
VERSION = "1.14.2"

DEFAULTS = {
    "listen": "0.0.0.0",
    "port": 2097,
    "path": "/relay/",
    "password": "",
    "sui_url": "http://127.0.0.1:2095/app/",
    "sui_user": "admin",
    "sui_pass": "",
    "public_host": "",
    "port_min": 10000,
    "port_max": 60000,
    "check_url": "https://www.gstatic.com/generate_204",
    "geo_lookup": True,
    "auto_firewall": True,
    "sui_restart_cmd": "systemctl restart s-ui",
    "sui_stop_cmd": "systemctl stop s-ui",
    "sui_start_cmd": "systemctl start s-ui",
    "sui_db": "/usr/local/s-ui/db/s-ui.db",
    "tg_token": "",
    "tg_chat": "",
    "health_interval_min": 5,
    "health_fail_times": 2,
    "reserve_ports": True,
    "cert_file": "",
    "key_file": "",
}


def load_config():
    cfg = dict(DEFAULTS)
    with open(CONFIG_PATH, encoding="utf-8") as f:
        cfg.update(json.load(f))
    if not cfg["path"].startswith("/"):
        cfg["path"] = "/" + cfg["path"]
    if not cfg["path"].endswith("/"):
        cfg["path"] += "/"
    if not cfg["sui_url"].endswith("/"):
        cfg["sui_url"] += "/"
    return cfg


CFG = None
LOCK = threading.Lock()  # serialize all write operations against s-ui


# ---------------------------------------------------------------- s-ui API --
class SuiError(Exception):
    pass


class Sui:
    def __init__(self, cfg):
        self.cfg = cfg
        self.base = cfg["sui_url"] + "api/"
        self.jar = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self.jar), urllib.request.ProxyHandler({})]
        if cfg["sui_url"].startswith("https://"):
            import ssl
            # s-ui 面板开了 HTTPS 时，本机回环访问证书域名对不上，这里只对本机连接跳过校验
            handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
        self.opener = urllib.request.build_opener(*handlers)
        # s-ui 设置了「面板域名」时会拒绝 Host 不匹配的请求；同时 s-ui 用 Host 生成客户链接里的地址
        self.host = cfg.get("sui_host") or cfg["public_host"] or None
        self.lock = threading.Lock()

    def _raw(self, method, action, params=None, form=None, host=None, timeout=30):
        url = self.base + action
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("X-Requested-With", "XMLHttpRequest")
        if host:
            req.add_header("Host", host)
        with self.opener.open(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "replace")
        try:
            return json.loads(body)
        except ValueError:
            raise SuiError("s-ui 返回了非 JSON 内容：" + body[:200])

    def login(self):
        res = self._raw("POST", "login", form={"user": self.cfg["sui_user"], "pass": self.cfg["sui_pass"]}, host=self.host)
        if not res.get("success"):
            raise SuiError("登录 s-ui 失败：" + str(res.get("msg")))

    def call(self, method, action, params=None, form=None, host=None, timeout=30):
        host = host or self.host
        for attempt in range(2):
            try:
                res = self._raw(method, action, params, form, host, timeout)
            except urllib.error.URLError as e:
                raise SuiError("连接 s-ui 失败：%s（检查 sui_url 配置）" % e)
            if not res.get("success") and "Invalid login" in str(res.get("msg")) and attempt == 0:
                with self.lock:
                    self.login()
                continue
            if not res.get("success"):
                raise SuiError(str(res.get("msg")))
            return res.get("obj")
        raise SuiError("s-ui 登录失效")

    # helpers
    def get(self, what, **params):
        obj = self.call("GET", what, params=params or None)
        return obj

    def save(self, obj, act, data, init_users=None):
        # s-ui 对所有 data 都做 json.Unmarshal，字符串（如要删除的 tag）也必须是 JSON 字符串
        form = {"object": obj, "action": act, "data": json.dumps(data, ensure_ascii=False)}
        if init_users is not None:
            form["initUsers"] = init_users
        return self.call("POST", "save", form=form)

    def load_all(self):
        o = self.call("GET", "load")
        return o

    def link_convert(self, link):
        return self.call("POST", "linkConvert", form={"link": link})

    def check_outbound(self, tag, link):
        return self.call("GET", "checkOutbound", params={"tag": tag, "link": link}, timeout=40)


SUI = None


# -------------------------------------------------------------- utilities --
ALNUM = string.ascii_letters + string.digits


def rand_pw(n=10):
    return "".join(secrets.choice(ALNUM) for _ in range(n))


def b64key(n):
    return base64.b64encode(secrets.token_bytes(n)).decode()


def client_config(name):
    """Same structure the s-ui panel generates for a new client."""
    u = str(uuid.uuid4())
    p = rand_pw()
    ss = b64key(32)
    return {
        "mixed": {"username": name, "password": p},
        "socks": {"username": name, "password": p},
        "http": {"username": name, "password": p},
        "shadowsocks": {"name": name, "password": ss},
        "shadowsocks16": {"name": name, "password": b64key(16)},
        "shadowtls": {"name": name, "password": ss},
        "vmess": {"name": name, "uuid": u, "alterId": 0},
        "vless": {"name": name, "uuid": u, "flow": "xtls-rprx-vision"},
        "anytls": {"name": name, "password": p},
        "trojan": {"name": name, "password": p},
        "naive": {"username": name, "password": p},
        "hysteria": {"name": name, "auth_str": p},
        "tuic": {"name": name, "uuid": u, "password": p},
        "hysteria2": {"name": name, "password": p},
    }


def is_ip(s):
    try:
        ipaddress.ip_address(s.strip("[]"))
        return True
    except ValueError:
        return False


def resolve(host):
    if is_ip(host):
        return host.strip("[]")
    try:
        return socket.gethostbyname(host)
    except OSError:
        return ""


SOCKS_RE = re.compile(r"^(socks5h?|socks4a?|socks|http|https)://(?:([^:@/]*)(?::([^@/]*))?@)?\[?([^\]/:@]+|[0-9a-fA-F:]+)\]?:(\d+)/?(?:#(.*))?$", re.I)


def parse_landing(raw):
    """Return (outbound_dict_without_tag, host, remark) or raise ValueError."""
    s = raw.strip()
    if not s:
        raise ValueError("空行")
    m = SOCKS_RE.match(s)
    if m:
        scheme, user, pw, host, port, remark = m.groups()
        scheme = scheme.lower()
        user = urllib.parse.unquote(user or "")
        pw = urllib.parse.unquote(pw or "")
        if scheme.startswith("socks") and user and not pw:
            # socks5://base64(user:pass)@host:port  (v2rayN style)
            try:
                dec = base64.b64decode(user + "=" * (-len(user) % 4)).decode()
                if ":" in dec:
                    user, pw = dec.split(":", 1)
            except Exception:
                pass
        if scheme.startswith("socks"):
            ob = {"type": "socks", "server": host, "server_port": int(port), "version": "4" if scheme.startswith("socks4") else "5"}
        else:
            ob = {"type": "http", "server": host, "server_port": int(port)}
            if scheme == "https":
                ob["tls"] = {"enabled": True, "server_name": host}
        if user:
            ob["username"] = user
            ob["password"] = pw
        return ob, host, urllib.parse.unquote(remark or "")
    if "://" in s:
        scheme = s.split("://", 1)[0].lower()
        if scheme not in ("vless", "vmess", "trojan", "hy", "hysteria", "hy2", "hysteria2", "ss", "shadowsocks", "tuic", "anytls"):
            raise ValueError("不支持的链接类型：" + scheme)
        ob = SUI.link_convert(s)
        if not isinstance(ob, dict) or not ob.get("type"):
            raise ValueError("链接解析失败")
        ob = dict(ob)
        remark = ob.pop("tag", "") or ""
        if "#" in s:
            remark = urllib.parse.unquote(s.rsplit("#", 1)[1])
        return ob, ob.get("server", ""), remark
    # IP:端口:账号:密码  /  IP:端口  /  IP 端口 账号 密码
    parts = [p for p in re.split(r"[:\s|,，]+", s) if p]
    if len(parts) >= 2 and parts[1].isdigit():
        host, port = parts[0], int(parts[1])
        ob = {"type": "socks", "server": host, "server_port": port, "version": "5"}
        if len(parts) >= 4:
            ob["username"] = parts[2]
            ob["password"] = ":".join(parts[3:])
        elif len(parts) == 3:
            raise ValueError("格式应为 IP:端口:账号:密码")
        return ob, host, ""
    raise ValueError("无法识别的格式")


GEO_CACHE = {}


def geo_lookup(ips):
    """ip -> 国家中文名, via ip-api.com batch (free, http)."""
    out = {}
    todo = []
    for ip in ips:
        if not ip:
            continue
        if ip in GEO_CACHE:
            out[ip] = GEO_CACHE[ip]
        elif ip not in todo:
            todo.append(ip)
    if todo and CFG.get("geo_lookup", True):
        for i in range(0, len(todo), 100):
            chunk = todo[i:i + 100]
            try:
                body = json.dumps([{"query": ip, "fields": "status,country,query", "lang": "zh-CN"} for ip in chunk]).encode()
                req = urllib.request.Request("http://ip-api.com/batch", data=body, headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=8) as r:
                    for item in json.loads(r.read().decode()):
                        if item.get("status") == "success":
                            GEO_CACHE[item["query"]] = item.get("country", "")
                            out[item["query"]] = item.get("country", "")
            except Exception:
                pass
    return out


def used_ports(data):
    ports = set()
    for inb in data.get("inbounds") or []:
        try:
            ports.add(int(inb.get("listen_port")))
        except (TypeError, ValueError):
            pass
    return ports


def port_free(p, need_udp):
    for kind in ([socket.SOCK_STREAM, socket.SOCK_DGRAM] if need_udp else [socket.SOCK_STREAM]):
        for fam, addr in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
            try:
                s = socket.socket(fam, kind)
            except OSError:
                continue
            try:
                s.bind((addr, p))
            except OSError:
                return False
            finally:
                s.close()
    return True


def pick_port(taken, need_udp):
    lo, hi = int(CFG["port_min"]), int(CFG["port_max"])
    for _ in range(500):
        p = random.randint(lo, hi)
        if p in taken:
            continue
        if port_free(p, need_udp):
            taken.add(p)
            return p
    raise SuiError("找不到可用端口")


def open_firewall(port, udp):
    if not CFG.get("auto_firewall", True):
        return ""
    protos = ["tcp"] + (["udp"] if udp else [])
    try:
        if shutil.which("ufw"):
            st = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=10).stdout
            if "Status: active" in st or "状态： 激活" in st:
                for pr in protos:
                    subprocess.run(["ufw", "allow", "%d/%s" % (port, pr)], capture_output=True, timeout=10)
                return "ufw"
        if shutil.which("firewall-cmd"):
            st = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True, timeout=10).stdout
            if "running" in st:
                for pr in protos:
                    subprocess.run(["firewall-cmd", "--permanent", "--add-port=%d/%s" % (port, pr)], capture_output=True, timeout=10)
                subprocess.run(["firewall-cmd", "--reload"], capture_output=True, timeout=20)
                return "firewalld"
    except Exception:
        pass
    return ""


def qr_svg(text, scale=6, border=4):
    q = qrencoder.QRCode(None, qrencoder.QRErrorCorrectLevel.M)
    q.addData(text)
    q.make()
    n = q.getModuleCount()
    size = (n + 2 * border) * scale
    path = []
    for r in range(n):
        for c in range(n):
            if q.isDark(r, c):
                path.append("M%d %dh%dv%dh-%dz" % ((c + border) * scale, (r + border) * scale, scale, scale, scale))
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" shape-rendering="crispEdges">'
            '<rect width="100%%" height="100%%" fill="#fff"/><path fill="#000" d="%s"/></svg>') % (size, size, size, size, "".join(path))


# ------------------------------------------------------------ relay model --
def build_relays(data):
    """Combine inbounds / outbounds / clients / route rules into relay rows."""
    inbounds = data.get("inbounds") or []
    outbounds = {o["tag"]: o for o in (data.get("outbounds") or []) if o.get("tag")}
    clients = data.get("clients") or []
    cfg = data.get("config") or {}
    rules = ((cfg.get("route") or {}).get("rules")) or []
    route_of, route_user = {}, {}
    for r in rules:
        if r.get("action", "route") == "route" and r.get("outbound"):
            for t in r.get("inbound") or []:
                route_of.setdefault(t, r["outbound"])
                for u in r.get("auth_user") or []:
                    route_user.setdefault((t, u), r["outbound"])
    clients_by_inb = {}
    for c in clients:
        try:
            ids = c.get("inbounds") or []
            if isinstance(ids, str):
                ids = json.loads(ids)
        except ValueError:
            ids = []
        for i in ids:
            clients_by_inb.setdefault(i, []).append(c)
    rows = []
    for inb in inbounds:
        itag = inb.get("tag")
        cl = clients_by_inb.get(inb.get("id"), [])
        if is_shared(itag):
            # 共用入站（如 443）：每个用户一行，按 auth_user 规则找各自的落地
            units = [(c.get("name"), c, route_user.get((itag, c.get("name")))) for c in cl]
        else:
            units = [(itag, next((c for c in cl if c.get("name") == itag), cl[0] if cl else None), route_of.get(itag))]
        for tag, main, ot in units:
          ob = outbounds.get(ot) if ot else None
          rows.append({
            "tag": tag,
            "inbound_tag": itag,
            "shared": is_shared(itag),
            "inbound_id": inb.get("id"),
            "type": "vless443" if is_shared(itag) else inb.get("type"),
            "port": inb.get("listen_port"),
            "outbound_tag": ot,
            "outbound_id": ob.get("id") if ob else None,
            "landing_type": ob.get("type") if ob else None,
            "landing": "本机直连" if ob and ob.get("type") == "direct" else (("%s:%s" % (ob.get("server"), ob.get("server_port"))) if ob and ob.get("server") else (ot or "")),
            "landing_user": (ob or {}).get("username", ""),
            "landing_info": landing_info(ob) if ob else None,
            "client_id": main.get("id") if main else None,
            "client_name": main.get("name") if main else None,
            "clients": 1 if is_shared(itag) else len(cl),
            "enable": bool(main.get("enable")) if main else None,
            "expiry": main.get("expiry") if main else None,
            "up": main.get("up") if main else 0,
            "down": main.get("down") if main else 0,
        })
    # 共用同一个落地出站的其他节点（同一落地的不同协议）
    by_out = {}
    for r in rows:
        if r["outbound_tag"]:
            by_out.setdefault(r["outbound_tag"], []).append(r)
    for r in rows:
        r["siblings"] = [{"tag": x["tag"], "type": x["type"], "port": x["port"]}
                         for x in by_out.get(r["outbound_tag"], []) if x["tag"] != r["tag"]]
    rows.sort(key=lambda r: (r.get("inbound_id") or 0, r.get("client_id") or 0), reverse=True)
    return rows


def landing_info(ob):
    """落地出站的完整信息（含账号密码），供页面展示和复制。"""
    q = urllib.parse.quote
    typ, host, port = ob.get("type"), ob.get("server", ""), ob.get("server_port", "")
    user, pw = ob.get("username", ""), ob.get("password", "")
    info = {"type": typ, "server": host, "port": port, "username": user, "password": pw}
    if typ in ("socks", "http"):
        scheme = "socks5" if typ == "socks" else ("https" if (ob.get("tls") or {}).get("enabled") else "http")
        auth = "%s:%s@" % (q(user, safe=""), q(pw, safe="")) if user else ""
        info["url"] = "%s://%s%s:%s" % (scheme, auth, host, port)
        info["plain"] = "%s:%s:%s:%s" % (host, port, user, pw) if user else "%s:%s" % (host, port)
    else:
        for k in ("uuid", "method", "flow"):
            if ob.get(k):
                info[k] = ob[k]
        tls = ob.get("tls") or {}
        if tls.get("server_name"):
            info["sni"] = tls["server_name"]
        if (tls.get("reality") or {}).get("public_key"):
            info["public_key"] = tls["reality"]["public_key"]
            info["short_id"] = tls["reality"].get("short_id", "")
    return info


def find_tls(data, kind):
    """kind = 'reality' or 'cert'. Returns tls id or 0."""
    for t in data.get("tls") or []:
        srv = t.get("server") or {}
        if isinstance(srv, str):
            try:
                srv = json.loads(srv)
            except ValueError:
                srv = {}
        is_reality = bool((srv.get("reality") or {}).get("enabled"))
        has_cert = bool(srv.get("certificate") or srv.get("certificate_path") or srv.get("key") or srv.get("key_path"))
        if kind == "reality" and is_reality:
            return t["id"]
        if kind == "cert" and not is_reality and has_cert:
            return t["id"]
    return 0


def unique_name(name, taken):
    n, k = name, 2
    while n in taken:
        n = "%s-%d" % (name, k)
        k += 1
    taken.add(n)
    return n


def core_running():
    try:
        st = SUI.call("GET", "status", params={"r": "sbd"}, timeout=5)
        return bool(((st or {}).get("sbd") or {}).get("running"))
    except Exception:
        return False


def wait_core(seconds=8):
    """After a config save s-ui restarts sing-box asynchronously; wait until it's back."""
    deadline = time.time() + seconds
    time.sleep(1.0)
    while time.time() < deadline:
        if core_running():
            return True
        time.sleep(0.7)
    return False


def ensure_core():
    """
    保存路由规则后调用。s-ui 1.3.10 在进程内重启 sing-box 不可靠：
      - 旧内核的监听端口（尤其 hysteria2 的 UDP）经常没释放，新内核启动失败（address already in use），所有节点掉线；
      - 异步重启和后续请求会竞争，内核状态错乱，之后的操作可能卡死。
    所以这里直接重启整个 s-ui 服务（干净启动，约 2~4 秒），内核没起来就再重启，最多 3 次。
    返回: "restarted" | "ok"(未配置重启命令但内核在跑) | "down"
    """
    reserve_ports()
    cmd = CFG.get("sui_restart_cmd") or ""
    if not cmd:
        return "ok" if wait_core(8) else "down"
    time.sleep(0.5)
    for attempt in range(3):
        try:
            subprocess.run(cmd, shell=True, timeout=60, capture_output=True)
        except Exception:
            pass
        deadline = time.time() + 20
        time.sleep(2)
        while time.time() < deadline:
            if core_running():
                return "restarted"
            time.sleep(1)
        sys.stderr.write("s-ui 内核未启动，第 %d 次重启后重试\n" % (attempt + 1))
    return "down"


RESERVED_FILE = "/etc/sysctl.d/99-relay-helper.conf"


def reserve_ports():
    """
    把所有入站端口加入 net.ipv4.ip_local_reserved_ports：系统给往外的连接分配本地端口时会避开它们，
    防止重启 s-ui 那一刻某个节点端口正好被往外的连接占着、导致内核启动失败。只影响自动分配，不影响程序主动监听。
    """
    if not CFG.get("reserve_ports", True):
        return
    try:
        data = SUI.load_all()
        ports = sorted({int(i.get("listen_port")) for i in data.get("inbounds") or [] if str(i.get("listen_port") or "").isdigit()})
        path = "/proc/sys/net/ipv4/ip_local_reserved_ports"
        if not ports or not os.access(path, os.W_OK):
            return
        cur = open(path).read().strip()
        mine_old = ""
        if os.path.exists(RESERVED_FILE):
            for line in open(RESERVED_FILE):
                if line.startswith("net.ipv4.ip_local_reserved_ports"):
                    mine_old = line.split("=", 1)[1].strip()
        # 保留别人设置的保留端口，替换掉我们自己上次写的部分
        def expand(s):
            out = set()
            for part in [x for x in s.replace(" ", "").split(",") if x]:
                a, _, b = part.partition("-")
                out.update(range(int(a), int(b or a) + 1)) if a.isdigit() else None
            return out
        others = expand(cur) - expand(mine_old)
        allp = sorted(others | set(ports))
        # 压缩成区间
        ranges, start, prev = [], None, None
        for p in allp:
            if start is None:
                start = prev = p
            elif p == prev + 1:
                prev = p
            else:
                ranges.append("%d-%d" % (start, prev) if prev > start else str(start)); start = prev = p
        if start is not None:
            ranges.append("%d-%d" % (start, prev) if prev > start else str(start))
        value = ",".join(ranges)
        with open(path, "w") as f:
            f.write(value)
        mine = ",".join(str(p) for p in ports)
        with open(RESERVED_FILE, "w") as f:
            f.write("# 由中转助手维护：s-ui 入站端口，避免被系统分配给往外的连接\nnet.ipv4.ip_local_reserved_ports = %s\n" % mine)
    except Exception as e:
        sys.stderr.write("reserve_ports: %s\n" % e)


# ----------------------------------------------------------- operations --
def server_ip():
    """中转机自己的公网 IP：先解析 public_host，解析不到再问外部服务。"""
    ip = resolve(CFG["public_host"])
    if ip and not ip.startswith(("127.", "10.", "192.168.")):
        return ip
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                v = r.read().decode().strip()
                if is_ip(v):
                    return v
        except Exception:
            pass
    return ip or CFG["public_host"]


def op_preview(body):
    lines = [l for l in (body.get("text") or "").splitlines() if l.strip()]
    customer = (body.get("customer") or "").strip()
    data = SUI.load_all()
    taken = {i.get("tag") for i in data.get("inbounds") or []} | {o.get("tag") for o in data.get("outbounds") or []} | {c.get("name") for c in data.get("clients") or []}
    if body.get("direct"):
        # 直连：不用落地，客户从中转机自己的 IP 出网。每条线路单独一个 direct 出站，方便分组、限额、以后换成落地。
        n = max(1, min(100, int(body.get("count") or 1)))
        ip = server_ip()
        country = geo_lookup([ip]).get(ip, "") if is_ip(ip) else ""
        items = []
        for _ in range(n):
            items.append({"raw": "本机直连", "outbound": {"type": "direct"}, "host": ip, "ip": ip, "direct": True,
                          "country": country, "error": "", "dup": [],
                          "name": unique_name("%s%s直连%s" % (country, customer, ip), taken)})
        return {"items": items}
    items = []
    for ln in lines:
        name_override = ""
        raw = ln.strip()
        # 支持 “名称 空格 链接” 或 “名称<TAB>链接”
        m = re.match(r"^(\S+)\s+((?:[a-zA-Z0-9]+://)\S+)$", raw)
        if m and not m.group(1).count("://"):
            name_override, raw = m.group(1), m.group(2)
        try:
            ob, host, remark = parse_landing(raw)
            items.append({"raw": raw, "outbound": ob, "host": host, "ip": resolve(host), "name_override": name_override, "error": ""})
        except Exception as e:
            items.append({"raw": raw, "error": str(e)})
    geo = geo_lookup([it.get("ip") for it in items if not it.get("error")])
    # 已有线路用过的落地：按「落地地址 + 端口 + 账号（或 uuid/密码）」判断是不是同一个落地
    existing = {}
    for g in groups_by_landing(build_relays(data), data):
        existing.setdefault(g["key"], []).append(g)
    seen = {}
    for i, it in enumerate(items):
        if it.get("error"):
            continue
        it["country"] = geo.get(it["ip"], "")
        base = it["name_override"] or ("%s%s%s" % (it["country"], customer, it["host"]))
        it["name"] = unique_name(base, taken)
        k = landing_key(it["outbound"])
        it["dup"] = [{"tag": g["main"], "types": g["types"], "tags": g["tags"]} for g in existing.get(k, [])]
        if k in seen:
            it["dup_in_batch"] = seen[k] + 1  # 与本次粘贴的第几行重复（从 1 数）
        else:
            seen[k] = i
    return {"items": items}


def landing_key(ob):
    """同一个落地的判断依据：类型 + 地址 + 端口 + 身份（账号 / uuid / 密码）。"""
    ident = ob.get("username") or ob.get("uuid") or ob.get("password") or ""
    return "%s|%s|%s|%s" % (ob.get("type"), str(ob.get("server", "")).lower(), ob.get("server_port"), ident)


def groups_by_landing(rows, data):
    """把线路按落地出站分组，返回 [{key, main, tags, types}]。"""
    obs = {o.get("tag"): o for o in data.get("outbounds") or []}
    by_out = {}
    for r in rows:
        if r.get("outbound_tag") in obs:
            by_out.setdefault(r["outbound_tag"], []).append(r)
    order = {"vless": 0, "vless443": 1, "hysteria2": 2, "socks": 3}
    out = []
    for ot, rs in by_out.items():
        rs.sort(key=lambda r: (order.get(r["type"], 9), r.get("inbound_id") or 0))
        out.append({"key": landing_key(obs[ot]), "main": rs[0]["tag"], "tags": [r["tag"] for r in rs],
                    "types": sorted({r["type"] for r in rs}, key=lambda x: order.get(x, 9))})
    return out


PROTO_SUFFIX = {"vless": "", "hysteria2": "-HY2", "socks": "-S5"}
PROTO_LABEL = {"vless": "VLESS-Reality", "hysteria2": "Hysteria2", "socks": "SOCKS5", "vless443": "VLESS-443共用"}
PROTO_SUFFIX["vless443"] = "-443"
SHARED_PREFIX = "共用"


def is_shared(tag):
    """共用入站：多个客户共用一个端口（默认 443），按用户名分流到各自落地。"""
    return isinstance(tag, str) and re.fullmatch(SHARED_PREFIX + r"\d+-VLESS", tag) is not None


def _ensure_shared(data, tls_id, taken_ports):
    """找到或建好共用 VLESS-Reality 入站，返回 (tag, id, 需要加的兜底规则)。"""
    port = int(CFG.get("shared_port") or 443)
    tag = "%s%d-VLESS" % (SHARED_PREFIX, port)
    for i in data.get("inbounds") or []:
        if i.get("tag") == tag:
            return tag, i["id"], []
    for i in data.get("inbounds") or []:
        if str(i.get("listen_port")) == str(port):
            raise SuiError("端口 %d 已被节点「%s」占用。先在线路管理里用「换端口」把它换到别的端口，再建共用节点" % (port, i.get("tag")))
    if not port_free(port, False):
        raise SuiError("端口 %d 被这台服务器上的其他程序占用（比如 nginx），共用节点用不了" % port)
    inb = {"type": "vless", "tag": tag, "listen": "::", "listen_port": port, "tls_id": tls_id, "addrs": [],
           "out_json": {}, "transport": {}}
    res = SUI.save("inbounds", "new", inb, init_users="")
    iid = next((i["id"] for i in (res or {}).get("inbounds") or [] if i.get("tag") == tag), None)
    if not iid:
        raise SuiError("共用入站创建后未找到 id")
    taken_ports.add(port)
    data.setdefault("inbounds", []).append({"id": iid, "tag": tag, "listen_port": port, "type": "vless"})
    try:
        ensure_clash_api()  # 共用端口按客户统计设备要用（随后保存路由时会重启 s-ui 生效）
    except Exception as e:
        sys.stderr.write("clash api: %s\n" % e)
    open_firewall(port, False)
    # 兜底：共用入站上没匹配到任何用户规则的连接一律拒绝
    return tag, iid, [{"inbound": [tag], "action": "reject"}]


def _make_shared_user(name, shared, expiry, group, outbound_tag):
    tag, iid, extra = shared
    client = {"enable": True, "name": name, "config": client_config(name), "inbounds": [iid],
              "links": [], "volume": 0, "expiry": int(expiry or 0), "up": 0, "down": 0,
              "desc": "中转助手创建（共用 %s）" % tag, "group": group or ""}
    res = SUI.save("clients", "new", client)
    cid = next((c["id"] for c in (res or {}).get("clients") or [] if c.get("name") == name), None)
    if not cid:
        raise SuiError("用户创建后未找到 id")
    port = int(CFG.get("shared_port") or 443)
    return {"name": name, "protocol": "vless443", "port": port, "client_id": cid, "ok": True, "firewall": "",
            "outbound": outbound_tag, "shared": True,
            "rules": [{"inbound": [tag], "auth_user": [name], "action": "route", "outbound": outbound_tag}] + extra}


def _prepare(data, protos):
    """检查协议需要的 TLS 配置，返回 {proto: tls_id}，以及已占用的名字和端口。"""
    tls = {}
    for proto in protos:
        if proto in ("vless", "vless443"):
            tls[proto] = find_tls(data, "reality")
            if not tls[proto]:
                raise SuiError("s-ui 里没有 Reality 配置。请先在面板「TLS 设置」里添加一个 reality 类型的配置")
        elif proto == "hysteria2":
            tls[proto] = find_tls(data, "cert")
            if not tls[proto]:
                raise SuiError("s-ui 里没有证书类 TLS 配置（hysteria2 需要）。请先在面板「TLS 设置」里添加")
        elif proto == "socks":
            tls[proto] = 0
        else:
            raise SuiError("不支持的入站协议：" + proto)
    taken_names = {i.get("tag") for i in data.get("inbounds") or []} | {o.get("tag") for o in data.get("outbounds") or []} | {c.get("name") for c in data.get("clients") or []}
    taken_ports = used_ports(data)
    settings = SUI.get("settings") or {}
    for k in ("webPort", "subPort"):
        try:
            taken_ports.add(int(settings.get(k)))
        except (TypeError, ValueError):
            pass
    return tls, taken_names, taken_ports


def _make_inbound(name, proto, tls_id, expiry, group, taken_ports, outbound_tag):
    """建一个入站 + 用户。成功返回结果 dict（含要加的路由规则）；失败时回滚自己建的部分并抛异常。"""
    created = {}
    try:
        port = pick_port(taken_ports, proto == "hysteria2")
        inb = {"type": proto, "tag": name, "listen": "::", "listen_port": port, "tls_id": tls_id, "addrs": [], "out_json": {}}
        if proto == "hysteria2":
            inb["ignore_client_bandwidth"] = True
        if proto == "vless":
            inb["transport"] = {}
        res = SUI.save("inbounds", "new", inb, init_users="")
        inb_id = next((i["id"] for i in (res or {}).get("inbounds") or [] if i.get("tag") == name), None)
        if not inb_id:
            raise SuiError("入站创建后未找到 id")
        created["inbound"] = name
        client = {"enable": True, "name": name, "config": client_config(name), "inbounds": [inb_id],
                  "links": [], "volume": 0, "expiry": int(expiry or 0), "up": 0, "down": 0,
                  "desc": "中转助手创建", "group": group or ""}
        res = SUI.save("clients", "new", client)
        cid = next((c["id"] for c in (res or {}).get("clients") or [] if c.get("name") == name), None)
        created["client"] = cid
        fw = open_firewall(port, proto == "hysteria2")
        return {"name": name, "protocol": proto, "port": port, "client_id": cid, "ok": True, "firewall": fw,
                "outbound": outbound_tag,
                # 第二条是兜底：用户停用/过期后 SOCKS5 入站会变成免认证，没匹配上落地规则的连接一律拒绝，
                # 否则会从中转机直接出网（变成公开代理）
                "rules": [{"inbound": [name], "auth_user": [name], "action": "route", "outbound": outbound_tag},
                          {"inbound": [name], "action": "reject"}]}
    except Exception:
        _rollback({"client_id": created.get("client"), "name": name if created.get("inbound") else None})
        raise


def _rollback(r, outbound=None):
    for obj, key in (("clients", r.get("client_id")), ("inbounds", r.get("name")), ("outbounds", outbound)):
        try:
            if key:
                SUI.save(obj, "del", key)
        except Exception:
            pass


def _apply_rules(results, new_outbounds):
    """一次性写入这批路由规则并重启 s-ui；失败则整批回滚。返回 core 状态。"""
    new_rules = [x for r in results if r.get("ok") and "rules" in r for x in r.pop("rules")]
    if not new_rules:
        return "ok"
    # 兜底拒绝规则必须排在同一入站的所有用户规则后面（共用入站一批会有多个用户）
    rej = lambda x: x.get("action") == "reject" and not x.get("auth_user")
    new_rules = [x for x in new_rules if not rej(x)] + [x for x in new_rules if rej(x)]
    cfg = SUI.get("config")
    cfg = cfg.get("config", cfg) if isinstance(cfg, dict) and isinstance(cfg.get("config"), dict) else cfg
    rules = cfg.setdefault("route", {}).setdefault("rules", [])
    pos = 0
    while pos < len(rules) and rules[pos].get("action") in ("sniff", "hijack-dns"):
        pos += 1
    rules[pos:pos] = new_rules
    try:
        SUI.save("config", "edit", cfg)
    except Exception as e:
        # 路由没保存成功：回滚这一批，避免留下没有路由（会从中转机直出）的入站
        for r in results:
            if r.get("ok"):
                _rollback(r)
                r.update(ok=False, error="保存路由失败，已回滚：%s" % e)
        for ob in new_outbounds:
            _rollback({}, ob)
        return "ok"
    return ensure_core()


def op_create(body):
    items = [it for it in body.get("items") or [] if not it.get("error") and it.get("name")]
    protos = body.get("protocols") or [body.get("protocol") or "vless"]
    protos = [p for p in dict.fromkeys(protos) if p]
    expiry = int(body.get("expiry") or 0)
    group = body.get("customer") or ""
    if not items:
        raise SuiError("没有可创建的线路")
    if not protos:
        raise SuiError("请至少选择一个入站协议")
    with LOCK:
        data = SUI.load_all()
        tls, taken_names, taken_ports = _prepare(data, protos)
        results, new_outbounds, shared = [], [], []
        for it in items:
            base = unique_name(it["name"], taken_names) if it["name"] in taken_names else it["name"]
            taken_names.add(base)
            ob = dict(it["outbound"])
            ob["tag"] = base
            try:
                SUI.save("outbounds", "new", ob)
            except Exception as e:
                results.append({"name": base, "ok": False, "error": "落地出站创建失败：%s" % e})
                continue
            made = []
            for i, proto in enumerate(protos):
                name = base if i == 0 else unique_name(base + PROTO_SUFFIX[proto], taken_names)
                taken_names.add(name)
                try:
                    if proto == "vless443":
                        if not shared:
                            shared.append(_ensure_shared(data, tls[proto], taken_ports))
                        made.append(_make_shared_user(name, shared[0], expiry, group, base))
                        shared[0] = shared[0][:2] + ([],)  # 兜底规则只加一次
                    else:
                        made.append(_make_inbound(name, proto, tls[proto], expiry, group, taken_ports, base))
                except Exception as e:
                    made.append({"name": name, "protocol": proto, "ok": False, "error": str(e)})
            if not any(m["ok"] for m in made):
                _rollback({}, base)  # 一个入站都没建成：落地出站也删掉
            else:
                new_outbounds.append(base)
            results.extend(made)
        core = _apply_rules(results, new_outbounds)
        init_group_limits([o for o in new_outbounds if any(r.get("ok") and r.get("outbound") == o for r in results)],
                          body.get("quota_gb"), body.get("devices"))
    for r in results:
        if r.get("ok") and r.get("client_id"):
            r["links"] = client_links(r["client_id"])
    return {"results": results, "core": core}


def op_add_protocol(body):
    """给已有线路加其他协议的入站，共用同一个落地出站，到期时间和客户分组跟原线路一致。"""
    tags = list(dict.fromkeys(body.get("tags") or []))
    protos = [p for p in dict.fromkeys(body.get("protocols") or []) if p]
    if not tags or not protos:
        raise SuiError("请选择线路和要添加的协议")
    with LOCK:
        data = SUI.load_all()
        rows = {r["tag"]: r for r in build_relays(data)}
        groups = {c.get("id"): c.get("group", "") for c in data.get("clients") or []}
        tls, taken_names, taken_ports = _prepare(data, protos)
        results, shared = [], []
        for t in tags:
            row = rows.get(t)
            if not row or not row.get("outbound_tag"):
                results.append({"name": t, "ok": False, "error": "找不到这条线路的落地"})
                continue
            have = {s["type"] for s in row.get("siblings") or []} | {row["type"]}
            base = re.sub(r"-(HY2|S5|VL|443)(-\d+)?$", "", t)
            for proto in protos:
                if proto in have:
                    results.append({"name": t, "protocol": proto, "ok": False, "skipped": True,
                                    "error": "这个落地已经有 %s 节点" % PROTO_LABEL.get(proto, proto)})
                    continue
                suffix = PROTO_SUFFIX[proto] or "-VL"
                name = unique_name(base + suffix, taken_names)
                taken_names.add(name)
                try:
                    if proto == "vless443":
                        if not shared:
                            shared.append(_ensure_shared(data, tls[proto], taken_ports))
                        results.append(_make_shared_user(name, shared[0], row.get("expiry") or 0,
                                                         groups.get(row.get("client_id"), ""), row["outbound_tag"]))
                        shared[0] = shared[0][:2] + ([],)
                    else:
                        results.append(_make_inbound(name, proto, tls[proto], row.get("expiry") or 0,
                                                     groups.get(row.get("client_id"), ""), taken_ports, row["outbound_tag"]))
                except Exception as e:
                    results.append({"name": name, "protocol": proto, "ok": False, "error": str(e)})
        core = _apply_rules(results, [])
    for r in results:
        if r.get("ok") and r.get("client_id"):
            r["links"] = client_links(r["client_id"])
    return {"results": results, "core": core}


def client_links(cid):
    c = SUI.get("clients", id=str(cid))
    if isinstance(c, dict):
        c = c.get("clients", c)
    if isinstance(c, list):
        c = c[0] if c else {}
    links = c.get("links") or []
    if isinstance(links, str):
        links = json.loads(links)
    return [l.get("uri") for l in links if l.get("uri")]


def op_list(body):
    data = SUI.load_all()
    with LIM_LOCK:
        lim = json.loads(json.dumps(LIMITS))
    return {"relays": build_relays(data), "now": int(time.time()), "public_host": CFG["public_host"],
            "unprotected": [t for t, _ in unprotected_inbounds(data)], "limits": lim, "online": dict(ONLINE),
            "health": dict(HEALTH), "health_last": HEALTH_META.get("last", 0), "failover": fo_summary(),
            "fw_error": FW_STATE["error"], "version": VERSION, "pool_auto": [k for k, v in (POOL.get("auto") or {}).items() if v]}


def op_links(body):
    out = []
    for cid in body.get("client_ids") or []:
        for u in client_links(cid):
            out.append({"client_id": cid, "uri": u, "svg": qr_svg(u)})
    return {"links": out}


def op_qr(body):
    return {"svg": qr_svg(body.get("text") or "")}


def op_check(body):
    tags = body.get("tags") or []
    url = body.get("url") or CFG["check_url"]

    def one(t):
        try:
            r = SUI.check_outbound(t, url) or {}
            return {"tag": t, "ok": bool(r.get("OK") or r.get("ok")), "delay": r.get("Delay") or r.get("delay"), "error": r.get("Error") or r.get("error") or ""}
        except Exception as e:
            return {"tag": t, "ok": False, "error": str(e)}
    with ThreadPoolExecutor(max_workers=8) as ex:
        return {"results": list(ex.map(one, tags))}


def op_check_raw(body):
    """Test landings before creating: temp outbounds, check, delete."""
    items = [it for it in body.get("items") or [] if not it.get("error")]
    url = body.get("url") or CFG["check_url"]
    tmp = []
    with LOCK:
        for it in items:
            t = "__relay_check_%s" % secrets.token_hex(4)
            ob = dict(it["outbound"])
            ob["tag"] = t
            try:
                SUI.save("outbounds", "new", ob)
                tmp.append((it.get("raw"), t))
            except Exception as e:
                tmp.append((it.get("raw"), None, str(e)))
        res = []
        try:
            def one(x):
                if x[1] is None:
                    return {"raw": x[0], "ok": False, "error": x[2]}
                try:
                    r = SUI.check_outbound(x[1], url) or {}
                    return {"raw": x[0], "ok": bool(r.get("OK")), "delay": r.get("Delay"), "error": r.get("Error") or ""}
                except Exception as e:
                    return {"raw": x[0], "ok": False, "error": str(e)}
            with ThreadPoolExecutor(max_workers=8) as ex:
                res = list(ex.map(one, tmp))
        finally:
            for x in tmp:
                if x[1]:
                    try:
                        SUI.save("outbounds", "del", x[1])
                    except Exception:
                        pass
    return {"results": res}


def op_replace(body):
    tag = body.get("tag")
    raw = body.get("landing") or ""
    with LOCK:
        data = SUI.load_all()
        rows = {r["tag"]: r for r in build_relays(data)}
        row = rows.get(tag)
        if not row or not row.get("outbound_id"):
            raise SuiError("找不到这条线路的落地出站")
        if isinstance(body.get("outbound"), dict):
            ob = dict(body["outbound"])  # 落地库里已解析好的
        else:
            ob, host, remark = parse_landing(raw)
        ob["tag"] = row["outbound_tag"]
        ob["id"] = row["outbound_id"]
        SUI.save("outbounds", "edit", ob)
        with FO_LOCK:
            f = FO.get(row["outbound_tag"])
            if f:  # 有备用落地：换的是当前在用的那个
                side = f.get("active", "primary")
                f[side] = _ob_clean(ob)
                f.pop("pcountry" if side == "primary" else "bcountry", None)
                _fo_fill_country(f)
                FO_STATE.pop(row["outbound_tag"], None)
                save_fo()
    chk = op_check({"tags": [row["outbound_tag"]]})["results"][0]
    return {"ok": True, "landing": "%s:%s" % (ob.get("server"), ob.get("server_port")), "check": chk}


def full_inbound(iid):
    r = SUI.get("inbounds", id=str(iid))
    lst = r.get("inbounds") if isinstance(r, dict) else r
    if not lst:
        raise SuiError("找不到入站 %s" % iid)
    return lst[0]


def op_change_port(body):
    """
    更换入站端口（客户当地封端口时用）。端口在客户链接里，换完要把新链接发给客户。
    tags: 要换的节点；port: 只换一个节点时可指定端口，留空随机。
    """
    tags = list(dict.fromkeys(body.get("tags") or []))
    want = body.get("port")
    if want not in (None, ""):
        want = int(want)
        if len(tags) != 1:
            raise SuiError("指定端口时一次只能换一个节点")
        if not 1 <= want <= 65535:
            raise SuiError("端口范围 1-65535")
    else:
        want = None
    out, changed = [], []
    with LOCK:
        data = SUI.load_all()
        rows = {r["tag"]: r for r in build_relays(data)}
        taken = used_ports(data)
        for t in tags:
            row = rows.get(t)
            if not row:
                out.append({"tag": t, "ok": False, "error": "不存在"})
                continue
            try:
                if row.get("shared"):
                    raise SuiError("443 共用节点所有客户共用一个端口，不能单独换端口；可以给这条线路加一个独立端口的协议")
                inb = full_inbound(row["inbound_id"])
                udp = inb.get("type") in ("hysteria2", "hysteria", "tuic")
                old = inb.get("listen_port")
                if want is not None:
                    if want == old:
                        raise SuiError("和原端口相同")
                    if want in taken or not port_free(want, udp):
                        raise SuiError("端口 %d 已被占用" % want)
                    port = want
                    taken.add(port)
                else:
                    port = pick_port(taken, udp)
                inb["listen_port"] = port
                if isinstance(inb.get("out_json"), dict) and "server_port" in inb["out_json"]:
                    inb["out_json"]["server_port"] = port
                SUI.save("inbounds", "edit", inb)
                fw = open_firewall(port, udp)
                changed.append(t)
                out.append({"tag": t, "ok": True, "old": old, "port": port, "firewall": fw, "client_id": row.get("client_id"), "type": inb.get("type")})
            except Exception as e:
                out.append({"tag": t, "ok": False, "error": str(e)})
        core = ensure_core() if changed else "ok"
    for r in out:
        if r.get("ok") and r.get("client_id"):
            try:
                r["links"] = client_links(r["client_id"])
                r["svg"] = qr_svg(r["links"][0]) if r["links"] else ""
            except Exception as e:
                r["links"], r["error"] = [], "端口已换，但获取新链接失败：%s" % e
    return {"results": out, "core": core}


def full_client(cid):
    c = SUI.get("clients", id=str(cid))
    if isinstance(c, dict):
        c = c.get("clients", c)
    if isinstance(c, list):
        c = c[0] if c else None
    if not c:
        raise SuiError("找不到用户 %s" % cid)
    for k in ("config", "inbounds", "links"):
        if isinstance(c.get(k), str):
            try:
                c[k] = json.loads(c[k])
            except ValueError:
                pass
    return c


def op_update_clients(body):
    ids = body.get("client_ids") or []
    out = []
    with LOCK:
        for cid in ids:
            try:
                c = full_client(cid)
                if "expiry" in body:
                    c["expiry"] = int(body["expiry"] or 0)
                    if c["expiry"] == 0 or c["expiry"] > time.time():
                        c["enable"] = True
                if "enable" in body:
                    c["enable"] = bool(body["enable"])
                if body.get("reset_traffic"):
                    c["up"] = c["down"] = 0
                SUI.save("clients", "edit", c)
                out.append({"client_id": cid, "ok": True})
            except Exception as e:
                out.append({"client_id": cid, "ok": False, "error": str(e)})
    if body.get("reset_traffic"):  # 续期并清零流量：清掉这些线路的“超流量”标记
        data = SUI.load_all()
        ids = set(ids)
        keys = {okey_of(r) for r in build_relays(data) if r.get("client_id") in ids}
        with LIM_LOCK:
            for k in keys:
                if (LIMITS.get(k) or {}).get("over"):
                    LIMITS[k]["over"] = False
            save_limits()
    return {"results": out}


def op_delete(body):
    """
    顺序：用户 → 入站 → 路由规则(只移除真正删掉的入站) → 等内核恢复 → 落地出站。
    任何一步失败都不会留下“入站还在但路由规则没了”的情况（那会让流量从中转机直出）。
    """
    tags = list(dict.fromkeys(body.get("tags") or []))
    out = []
    with LOCK:
        data = SUI.load_all()
        rows = {r["tag"]: r for r in build_relays(data)}
        deleted, deleted_rows, del_users = set(), set(), set()
        for t in tags:
            row = rows.get(t)
            if not row:
                out.append({"tag": t, "ok": False, "error": "不存在"})
                continue
            try:
                if row.get("shared"):
                    if row.get("client_id"):
                        SUI.save("clients", "del", row["client_id"])
                    del_users.add((row["inbound_tag"], t))
                    deleted_rows.add(t)
                    out.append({"tag": t, "ok": True})
                    continue
                if row.get("client_id"):
                    c = full_client(row["client_id"])
                    ids = [i for i in (c.get("inbounds") or []) if i != row["inbound_id"]]
                    if ids:  # 这个用户还挂在别的入站上：只解绑
                        c["inbounds"] = ids
                        SUI.save("clients", "edit", c)
                    else:
                        SUI.save("clients", "del", row["client_id"])
                SUI.save("inbounds", "del", t)
                deleted.add(t)
                deleted_rows.add(t)
                out.append({"tag": t, "ok": True})
            except Exception as e:
                out.append({"tag": t, "ok": False, "error": str(e)})
        core = "ok"
        if deleted or del_users:
            cfg = SUI.get("config")
            cfg = cfg.get("config", cfg) if isinstance(cfg, dict) and isinstance(cfg.get("config"), dict) else cfg
            rules = (cfg.get("route") or {}).get("rules") or []
            newrules = []
            for r in rules:
                inb = r.get("inbound")
                if inb and len(inb) == 1 and r.get("auth_user") and any((inb[0], u) in del_users for u in r["auth_user"]):
                    au = [u for u in r["auth_user"] if (inb[0], u) not in del_users]
                    if not au:
                        continue  # 共用入站上这个用户的分流规则
                    r = dict(r)
                    r["auth_user"] = au
                if inb and any(x in deleted for x in inb):
                    keep = [x for x in inb if x not in deleted]
                    if not keep:
                        continue
                    r = dict(r)
                    r["inbound"] = keep
                    if r.get("auth_user"):
                        r["auth_user"] = [u for u in r["auth_user"] if u not in deleted]
                        if not r["auth_user"]:
                            r.pop("auth_user")
                newrules.append(r)
            still_used = {r.get("outbound") for r in newrules}
            if newrules != rules:
                cfg["route"]["rules"] = newrules
                SUI.save("config", "edit", cfg)
                core = ensure_core()
            for t in deleted_rows:
                ot = rows[t].get("outbound_tag")
                if ot and ot not in still_used and ot != "direct":
                    try:
                        SUI.save("outbounds", "del", ot)
                        drop_group_limits([ot])
                        with SUBS_LOCK:
                            if SUBS.pop(ot, None):
                                save_subs()
                        with FO_LOCK:
                            f = FO.pop(ot, None)
                            FO_STATE.pop(ot, None)
                            if f:
                                save_fo()
                                SUI.save("outbounds", "del", f["standby"])
                    except Exception:
                        pass
    return {"results": out, "core": core}


def unprotected_inbounds(data):
    """
    找出缺少兜底拒绝规则的中转入站：有路由规则把它送到非 direct 的落地、且它的所有用户都被这些规则覆盖，
    但后面没有 reject 规则。返回 [(tag, 插入位置之前的最后一条规则下标)]。
    """
    cfg = data.get("config") or {}
    rules = ((cfg.get("route") or {}).get("rules")) or []
    out = []
    for inb in data.get("inbounds") or []:
        tag = inb.get("tag")
        idx = [i for i, r in enumerate(rules) if tag in (r.get("inbound") or [])]
        routes = [rules[i] for i in idx if rules[i].get("action", "route") == "route" and rules[i].get("outbound") not in (None, "direct")]
        if not routes:
            continue
        if any(rules[i].get("action") == "reject" and rules[i].get("inbound") == [tag] and len(rules[i]) == 2 for i in idx):
            continue
        if any(not r.get("auth_user") for r in routes):
            continue  # 规则不区分用户，已有的行为不动
        authed = {u for r in routes for u in r.get("auth_user") or []}
        users = set(inb.get("users") or [])
        if users and not users <= authed:
            continue  # 这个入站还有别的用户走默认出口，不能加拒绝
        last = max(i for i in idx if rules[i] in routes)
        out.append((tag, last))
    return out


def op_secure(body):
    with LOCK:
        data = SUI.load_all()
        todo = unprotected_inbounds(data)
        if not todo:
            return {"fixed": 0, "core": "ok"}
        cfg = SUI.get("config")
        cfg = cfg.get("config", cfg) if isinstance(cfg, dict) and isinstance(cfg.get("config"), dict) else cfg
        rules = cfg["route"]["rules"]
        for tag, last in sorted(todo, key=lambda x: -x[1]):  # 从后往前插，下标不乱
            rules.insert(last + 1, {"inbound": [tag], "action": "reject"})
        SUI.save("config", "edit", cfg)
        core = ensure_core()
    return {"fixed": len(todo), "tags": [t for t, _ in todo], "core": core}


def op_status(body):
    data = SUI.load_all()
    return {
        "ok": True, "version": VERSION, "public_host": CFG["public_host"],
        "reality_tls": find_tls(data, "reality"), "cert_tls": find_tls(data, "cert"),
        "inbounds": len(data.get("inbounds") or []), "clients": len(data.get("clients") or []),
        "unprotected": [t for t, _ in unprotected_inbounds(data)],
    }


OPS = {
    "status": op_status, "list": op_list, "preview": op_preview, "create": op_create,
    "check": op_check, "check_raw": op_check_raw, "replace": op_replace, "add_protocol": op_add_protocol,
    "update_clients": op_update_clients, "secure": op_secure, "delete": op_delete, "links": op_links, "qr": op_qr,
}

# ---------------------------------------------------- 流量限额 / 设备数限制 --
# 每条线路（同一个落地出站的几个协议节点）一组：流量合计、设备数合计。
LIMITS_PATH = os.path.join(os.path.dirname(CONFIG_PATH), "limits.json")
LIM_LOCK = threading.Lock()
LIMITS = {}          # okey -> {"quota_gb": float, "devices": int, "over": bool}
ONLINE = {}          # okey -> {"active": [ip...], "allowed": [ip...], "full": bool}
DEVICE_IDLE = 180    # 设备断开多少秒后释放名额
SEEN = {}            # okey -> {ip: [first_seen, last_seen]}
ALLOWED = {}         # okey -> [ip...]（按先来后到）
BANNED = {}          # okey -> {ip: 禁止到期时间戳（0=一直禁止，直到手动解除）}
CHAIN = "RELAYHELPER"
MON_LOCK = threading.RLock()
_last_rules = {"4": None, "6": None}
FW_STATE = {"error": ""}  # 防火墙规则下发失败的原因，页面上会提示


def load_limits():
    global LIMITS
    try:
        with open(LIMITS_PATH, encoding="utf-8") as f:
            d = json.load(f)
        LIMITS = d if isinstance(d, dict) else {}
    except Exception:
        LIMITS = {}


def save_limits():
    tmp = LIMITS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(LIMITS, f, ensure_ascii=False, indent=1)
    os.replace(tmp, LIMITS_PATH)


def okey_of(row):
    return row.get("outbound_tag") or ("#" + row["tag"])


def group_rows(rows):
    g = {}
    for r in rows:
        g.setdefault(okey_of(r), []).append(r)
    return g


def group_usage(rs):
    return sum((r.get("up") or 0) + (r.get("down") or 0) for r in rs)


def set_group_enable(rs, enable):
    for r in rs:
        if not r.get("client_id"):
            continue
        try:
            c = full_client(r["client_id"])
            if bool(c.get("enable")) != enable:
                c["enable"] = enable
                SUI.save("clients", "edit", c)
        except Exception as e:
            sys.stderr.write("set_group_enable: %s\n" % e)


def _hex_ip(h):
    if len(h) == 8:
        return socket.inet_ntop(socket.AF_INET, bytes.fromhex(h)[::-1])
    b = b"".join(bytes.fromhex(h[i:i + 8])[::-1] for i in range(0, 32, 8))
    ip = socket.inet_ntop(socket.AF_INET6, b)
    return ip[7:] if ip.startswith("::ffff:") and "." in ip else ip


def tcp_peers(ports):
    """{本地端口: {对端IP}}。除监听外的所有状态都算（含刚关闭的 TIME_WAIT），短连接也不会漏掉。"""
    out = {}
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                next(f)
                for line in f:
                    p = line.split()
                    if p[3] == "0A" or p[2].startswith("00000000:") or p[2].startswith("0" * 32 + ":"):
                        continue
                    lip, lport = p[1].split(":")
                    lport = int(lport, 16)
                    if lport in ports:
                        rip = _hex_ip(p[2].split(":")[0])
                        out.setdefault(lport, set()).add(rip)
        except Exception:
            pass
    return out


def udp_peers(ports):
    """hysteria2 走 UDP：从连接跟踪表里找对端 IP。"""
    out = {}
    lines = []
    try:
        with open("/proc/net/nf_conntrack") as f:
            lines = f.readlines()
    except Exception:
        if shutil.which("conntrack"):
            try:
                lines = subprocess.run(["conntrack", "-L", "-p", "udp"], capture_output=True, text=True, timeout=10).stdout.splitlines()
            except Exception:
                lines = []
    for line in lines:
        if " udp " not in " %s " % line and "udp" not in line.split()[:3]:
            continue
        m_src = re.search(r"src=(\S+)", line)
        m_dp = re.search(r"dport=(\d+)", line)
        if m_src and m_dp and int(m_dp.group(1)) in ports:
            out.setdefault(int(m_dp.group(1)), set()).add(m_src.group(1))
    return out


LOG_RE = re.compile(r"inbound/[\w-]+\[(.+?)\]\s*inbound connection from \[?([0-9a-fA-F:.]+?)\]?:\d+\s*$")
_log_prev = None


def log_peers(tags):
    """
    从 s-ui 内存日志里找「某 IP 连入某节点」（hysteria2 等 UDP 协议用这个，系统连接表看不到对端）。
    只统计上次巡检之后新出现的日志行；第一次只记位置。需要 s-ui 日志级别为 info 或更详细。
    返回 {tag: {ip}}
    """
    global _log_prev
    out = {}
    if not tags:
        return out
    try:
        lines = SUI.call("GET", "logs", params={"c": "5000", "l": "info"}, timeout=15) or []
    except Exception:
        return out
    cur = set(lines)
    if _log_prev is None:
        _log_prev = cur
        return out
    for line in lines:
        if line in _log_prev:
            continue
        m = LOG_RE.search(line)
        if m and m.group(1) in tags:
            ip = m.group(2)
            if ip.startswith("::ffff:"):
                ip = ip[7:]
            out.setdefault(m.group(1), set()).add(ip)
    _log_prev = cur
    return out


def _ipt(v):
    return "iptables" if v == "4" else "ip6tables"


def apply_firewall(blocks):
    """
    blocks: [(proto, port, allowed, banned)]
      banned 里的 IP 一律拒绝（被踢出的）；allowed 不为 None 时只放行这些 IP，其余拒绝（设备数满了）。
    规则逐包生效，被踢 IP 的现有连接也会马上断开。
    """
    if not shutil.which("iptables") or not shutil.which("iptables-restore"):
        # 没有 iptables：独立端口节点的踢出/设备限制都没法生效（443 共用节点还能靠断连接）
        FW_STATE["error"] = "服务器没有安装 iptables，踢出设备和设备数限制对独立端口的节点不生效。请在服务器执行：apt-get install -y iptables（CentOS 用 yum install -y iptables），然后 systemctl restart relay-helper"
        return
    errs = []
    for v in ("4", "6"):
        if not shutil.which(_ipt(v)) or not shutil.which(_ipt(v) + "-restore"):
            continue
        lines = ["*filter", ":%s - [0:0]" % CHAIN]
        for proto, port, allowed, banned in blocks:
            deny = "-j REJECT --reject-with tcp-reset" if proto == "tcp" else "-j DROP"
            for ip in banned:
                if (":" in ip) == (v == "6"):
                    lines.append("-A %s -p %s --dport %d -s %s %s" % (CHAIN, proto, port, ip, deny))
            if allowed is not None:
                for ip in allowed:
                    if (":" in ip) == (v == "6"):
                        lines.append("-A %s -p %s --dport %d -s %s -j RETURN" % (CHAIN, proto, port, ip))
                lines.append("-A %s -p %s --dport %d %s" % (CHAIN, proto, port, deny))
        lines.append("COMMIT")
        rules = "\n".join(lines) + "\n"
        try:
            # 自己的链挂在 INPUT 最前面；只改这条链，不碰系统原有规则（ufw/firewalld 重载后会自动补回）
            subprocess.run([_ipt(v), "-N", CHAIN], capture_output=True)
            if subprocess.run([_ipt(v), "-C", "INPUT", "-j", CHAIN], capture_output=True).returncode != 0:
                subprocess.run([_ipt(v), "-I", "INPUT", "1", "-j", CHAIN], capture_output=True)
                _last_rules[v] = None
            if rules != _last_rules[v]:
                r = subprocess.run([_ipt(v) + "-restore", "-n"], input=rules, text=True, capture_output=True)
                if r.returncode == 0:
                    _last_rules[v] = rules
                else:
                    sys.stderr.write("%s-restore: %s\n" % (_ipt(v), r.stderr.strip()))
                    if v == "4":
                        errs.append("%s 规则下发失败：%s" % (_ipt(v), r.stderr.strip()[:200]))
            elif v == "4" and subprocess.run([_ipt(v), "-C", "INPUT", "-j", CHAIN], capture_output=True).returncode != 0:
                errs.append("iptables 规则没能挂到 INPUT 链上")
        except Exception as e:
            sys.stderr.write("apply_firewall: %s\n" % e)
            if v == "4":
                errs.append("iptables 出错：%s" % e)
    FW_STATE["error"] = ("踢出设备和设备数限制对独立端口的节点可能不生效：" + "；".join(errs)) if errs else ""


# ------------------------------------------------- Clash API（共用端口按客户统计设备）--
# 443 共用入站上所有客户是同一个端口，系统连接表分不出谁是谁；sing-box 的 Clash API 能列出每条连接的
# 来源 IP 和走的落地出站（= 线路），就能按客户统计/限制设备。只监听 127.0.0.1，带随机密钥。
CLASH = {"url": None, "secret": None}


def _unwrap_cfg(cfg):
    return cfg.get("config", cfg) if isinstance(cfg, dict) and isinstance(cfg.get("config"), dict) else cfg


def ensure_clash_api():
    """没开就在 s-ui 配置里开 Clash API。返回 True 表示改了配置（需要重启 s-ui 生效）。"""
    cfg = _unwrap_cfg(SUI.get("config"))
    ca = (cfg.get("experimental") or {}).get("clash_api") or {}
    if ca.get("external_controller"):
        host, _, port = ca["external_controller"].rpartition(":")
        host = host.strip("[]")
        if host in ("", "0.0.0.0", "::"):
            host = "127.0.0.1"
        CLASH.update(url="http://%s:%s" % ("[%s]" % host if ":" in host else host, port), secret=ca.get("secret") or "")
        return False
    port = next((p for p in range(39090, 39190) if port_free(p, False)), None)
    if not port:
        return False
    sec = secrets.token_hex(16)
    cfg.setdefault("experimental", {})["clash_api"] = {"external_controller": "127.0.0.1:%d" % port, "secret": sec}
    SUI.save("config", "edit", cfg)
    CLASH.update(url="http://127.0.0.1:%d" % port, secret=sec)
    return True


def _clash(method, path):
    if not CLASH["url"]:
        return None
    req = urllib.request.Request(CLASH["url"] + path, method=method,
                                 headers={"Authorization": "Bearer %s" % CLASH["secret"]} if CLASH["secret"] else {})
    with urllib.request.urlopen(req, timeout=5) as r:
        body = r.read()
    return json.loads(body) if body else None


def clash_conns():
    try:
        return (_clash("GET", "/connections") or {}).get("connections") or []
    except Exception:
        return []


def clash_close(cid):
    try:
        _clash("DELETE", "/connections/" + urllib.parse.quote(cid))
    except Exception:
        pass


def monitor_once():
    with MON_LOCK:
        _monitor_once()


def _monitor_once():
    data = SUI.load_all()
    rows = build_relays(data)
    groups = group_rows(rows)
    now = time.time()
    with LIM_LOCK:
        lim = json.loads(json.dumps(LIMITS))
    # ---- 到期：s-ui 自己要过几分钟才处理，这里到期就马上停用（续期时会重新启用）
    expired = [r for r in rows if r.get("client_id") and r.get("enable") and (r.get("expiry") or 0) > 0 and r["expiry"] < now]
    if expired:
        with LOCK:
            set_group_enable(expired, False)
        sys.stderr.write("已到期停用：%s\n" % "、".join(r["tag"] for r in expired[:20]))
    # ---- 流量：整条线路合计，超了整组停用
    changed = False
    for k, L in lim.items():
        rs = groups.get(k)
        if not rs:
            continue
        q = float(L.get("quota_gb") or 0)
        if q > 0 and group_usage(rs) >= q * 1024 ** 3:
            if any(r.get("enable") for r in rs):
                with LOCK:
                    set_group_enable(rs, False)
                sys.stderr.write("线路 %s 流量用完，已停用\n" % k)
            if not L.get("over"):
                with LIM_LOCK:
                    LIMITS.setdefault(k, {})["over"] = True
                changed = True
    if changed:
        with LIM_LOCK:
            save_limits()
    # ---- 设备：整条线路所有端口上的不同客户 IP
    ports = {}
    for k, rs in groups.items():
        for r in rs:
            if r.get("port") and not r.get("shared"):  # 共用端口上分不出是哪个客户，不按端口统计
                ports[int(r["port"])] = (k, "udp" if r["type"] in ("hysteria2", "hysteria", "tuic") else "tcp")
    shared_in = {r["inbound_tag"]: int(r["port"]) for r in rows if r.get("shared") and r.get("port")}
    sconns = []  # (线路, ip, 连接 id)
    if shared_in:
        if not CLASH["url"]:
            try:
                with LOCK:
                    if ensure_clash_api():
                        ensure_core()
            except Exception as e:
                sys.stderr.write("clash api: %s\n" % e)
        for c in clash_conns():
            md = c.get("metadata") or {}
            if (md.get("type") or "").split("/", 1)[-1] not in shared_in:
                continue
            k = (c.get("chains") or [None])[0]
            ip = md.get("sourceIP") or ""
            if ip.startswith("::ffff:"):
                ip = ip[7:]
            if k in groups and ip:
                sconns.append((k, ip, c.get("id")))
    tp = tcp_peers({p for p, (k, pr) in ports.items() if pr == "tcp"})
    up = udp_peers({p for p, (k, pr) in ports.items() if pr == "udp"})
    udp_tags = {r["tag"]: okey_of(r) for r in rows if r.get("port") and not r.get("shared") and ports.get(int(r["port"]), ("", ""))[1] == "udp"}
    lp = log_peers(set(udp_tags))
    seen_now = {}
    keep = lambda i: i not in ("127.0.0.1", "::1") or CFG.get("count_loopback")
    for p, ips in list(tp.items()) + list(up.items()):
        seen_now.setdefault(ports[p][0], set()).update(i for i in ips if keep(i))
    for tag, ips in lp.items():
        seen_now.setdefault(udp_tags[tag], set()).update(i for i in ips if keep(i))
    for k, ip, _ in sconns:
        if keep(ip):
            seen_now.setdefault(k, set()).add(ip)
    blocks, online = [], {}
    sh_bad, sh_ok = {}, set()  # 共用端口：要拒绝的 (线路 -> ip)、各线路正常在用的 ip
    for k in list(BANNED):
        BANNED[k] = {ip: u for ip, u in BANNED[k].items() if u == 0 or u > now}
        if not BANNED[k] or k not in groups:
            BANNED.pop(k, None)
    for k, rs in groups.items():
        S = SEEN.setdefault(k, {})
        B = BANNED.get(k, {})
        for ip in seen_now.get(k, ()):
            if ip not in B:
                S.setdefault(ip, [now, now])[1] = now
        for ip in [ip for ip, (f, l) in S.items() if now - l > int(CFG.get("device_idle", DEVICE_IDLE))]:
            del S[ip]
        active = sorted(S, key=lambda ip: S[ip][0])
        n = int((lim.get(k) or {}).get("devices") or 0)
        A = [ip for ip in ALLOWED.get(k, []) if ip in S]
        if n > 0:
            for ip in active:
                if len(A) >= n:
                    break
                if ip not in A:
                    A.append(ip)
            ALLOWED[k] = A
            full = len(A) >= n
        else:
            ALLOWED.pop(k, None)
            full = False
        if any(r.get("shared") for r in rs):
            bad = set(B) | ({ip for ip in active if ip not in A} if full else set())
            if bad:
                sh_bad[k] = bad
            sh_ok.update(ip for ip in active if ip not in bad)
        if full or B:
            for r in rs:
                if r.get("port") and not r.get("shared"):
                    blocks.append((ports[int(r["port"])][1], int(r["port"]), A if full else None, list(B)))
        if active or n or B:
            online[k] = {"active": active, "allowed": A if n else active, "full": full,
                         "rejected": [ip for ip in active if n and ip not in A],
                         "banned": {ip: (int(u - now) if u else 0) for ip, u in B.items()}}
    for k in list(SEEN):
        if k not in groups:
            SEEN.pop(k, None)
    ONLINE.clear()
    ONLINE.update(online)
    # 共用端口不能用白名单（会挡住别的客户），改为只拒绝超额/被踢的 IP；
    # 同一个 IP 若也是别的客户正常在用的（比如同一个出口 NAT），不封端口，只断这条线路的连接
    if sh_bad:
        deny = set().union(*sh_bad.values()) - sh_ok
        for port in sorted(set(shared_in.values())):
            if deny:
                blocks.append(("tcp", port, None, sorted(deny)))
        for k, ip, cid in sconns:
            if ip in sh_bad.get(k, ()):
                clash_close(cid)
    apply_firewall(blocks)


def op_kick(body):
    """
    action: kick（踢出 ip，禁止 minutes 分钟，0=直到手动解除）| unban（解除禁止）| release（清空在线名单，不禁止）
    """
    tag, action = body.get("tag"), body.get("action") or "kick"
    data = SUI.load_all()
    rows = {r["tag"]: r for r in build_relays(data)}
    if tag not in rows:
        raise SuiError("找不到这条线路")
    k = okey_of(rows[tag])
    ips = body.get("ips") or ([body["ip"]] if body.get("ip") else [])
    now = time.time()
    with MON_LOCK:
        S, A, B = SEEN.setdefault(k, {}), ALLOWED.get(k, []), BANNED.setdefault(k, {})
        if action == "release":
            S.clear()
            ALLOWED.pop(k, None)
        elif action == "unban":
            for ip in ips:
                B.pop(ip, None)
        else:
            mins = float(body.get("minutes", 5))
            for ip in ips:
                B[ip] = 0 if mins <= 0 else now + mins * 60
                S.pop(ip, None)
                if ip in A:
                    A.remove(ip)
        if not B:
            BANNED.pop(k, None)
    _monitor_now()
    return {"online": ONLINE.get(k)}


def _monitor_now():
    try:
        monitor_once()
    except Exception as e:
        sys.stderr.write("monitor: %s\n" % e)


def monitor_loop():
    while True:
        try:
            monitor_once()
        except Exception as e:
            sys.stderr.write("monitor: %s\n" % e)
        time.sleep(int(CFG.get("monitor_interval", 10)))


def op_set_limits(body):
    tags = body.get("tags") or []
    data = SUI.load_all()
    rows = {r["tag"]: r for r in build_relays(data)}
    groups = group_rows(rows.values())
    keys = {okey_of(rows[t]) for t in tags if t in rows}
    reenable = []
    with LIM_LOCK:
        for k in keys:
            L = LIMITS.setdefault(k, {})
            if "quota_gb" in body:
                L["quota_gb"] = max(0.0, float(body.get("quota_gb") or 0))
            if "devices" in body:
                L["devices"] = max(0, int(body.get("devices") or 0))
            q = float(L.get("quota_gb") or 0)
            if L.get("over") and (q == 0 or group_usage(groups.get(k, [])) < q * 1024 ** 3):
                L["over"] = False
                reenable.append(k)
            if not L.get("quota_gb") and not L.get("devices") and not L.get("over"):
                LIMITS.pop(k, None)
        save_limits()
    _reenable(reenable, groups)
    return {"updated": len(keys)}


def _reenable(keys, groups):
    now = time.time()
    with LOCK:
        for k in keys:
            rs = [r for r in groups.get(k, []) if not r.get("expiry") or r["expiry"] > now]
            set_group_enable(rs, True)


def op_reset_traffic(body):
    tags = body.get("tags") or []
    data = SUI.load_all()
    rows = {r["tag"]: r for r in build_relays(data)}
    groups = group_rows(rows.values())
    keys = {okey_of(rows[t]) for t in tags if t in rows}
    with LOCK:
        for k in keys:
            for r in groups.get(k, []):
                if r.get("client_id"):
                    c = full_client(r["client_id"])
                    c["up"] = c["down"] = 0
                    SUI.save("clients", "edit", c)
    over = []
    with LIM_LOCK:
        for k in keys:
            if (LIMITS.get(k) or {}).get("over"):
                LIMITS[k]["over"] = False
                over.append(k)
        save_limits()
    _reenable(over, groups)
    return {"reset": len(keys)}


def init_group_limits(okeys, quota_gb, devices):
    if not (quota_gb or devices):
        return
    with LIM_LOCK:
        for k in okeys:
            LIMITS[k] = {"quota_gb": float(quota_gb or 0), "devices": int(devices or 0), "over": False}
        save_limits()


def drop_group_limits(okeys):
    with LIM_LOCK:
        hit = [k for k in okeys if k in LIMITS]
        for k in hit:
            LIMITS.pop(k, None)
        if hit:
            save_limits()


# ------------------------------------------------------- 设置 / Telegram --
SETTING_KEYS = ("tg_token", "tg_chat", "health_interval_min", "health_fail_times")


def save_config(updates):
    """原子写回 config.json 并更新内存里的配置。"""
    with open(CONFIG_PATH, encoding="utf-8-sig") as f:
        cur = json.load(f)
    cur.update(updates)
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cur, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_PATH)
    CFG.update(updates)


def tg_ready():
    return bool(CFG.get("tg_token") and CFG.get("tg_chat"))


def tg_send(text):
    if not tg_ready():
        return False, "未配置 Telegram"
    try:
        body = json.dumps({"chat_id": CFG["tg_chat"], "text": text[:4000], "disable_web_page_preview": True}).encode()
        req = urllib.request.Request("%s/bot%s/sendMessage" % (CFG.get("tg_api") or "https://api.telegram.org", CFG["tg_token"]), data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            res = json.loads(r.read().decode())
        return bool(res.get("ok")), res.get("description", "")
    except urllib.error.HTTPError as e:
        try:
            return False, json.loads(e.read().decode()).get("description", str(e))
        except Exception:
            return False, str(e)
    except Exception as e:
        return False, str(e)


def op_get_settings(body):
    s = {k: CFG.get(k) for k in SETTING_KEYS}
    tok = s.get("tg_token") or ""
    s["tg_token"] = ("••••" + tok[-4:]) if tok else ""
    s["tg_token_set"] = bool(tok)
    return {"settings": s, "health_last": HEALTH_META.get("last", 0)}


def op_save_settings(body):
    up = {}
    for k in SETTING_KEYS:
        if k not in body:
            continue
        v = body[k]
        if k == "tg_token":
            v = (v or "").strip()
            if v.startswith("••••"):
                continue  # 没改
        elif k == "tg_chat":
            v = str(v or "").strip()
        elif k == "health_interval_min":
            v = max(0, int(v or 0))
        elif k == "health_fail_times":
            v = max(1, int(v or 1))
        up[k] = v
    save_config(up)
    return {"saved": list(up)}


def op_tg_test(body):
    ok, err = tg_send("✅ 中转助手（%s）Telegram 通知测试成功" % CFG["public_host"])
    if not ok:
        raise SuiError("发送失败：%s" % err)
    return {}


# ------------------------------------------------------------ 落地自动巡检 --
HEALTH = {}        # okey -> {"ok", "delay", "error", "fails", "alerted", "ts", "landing", "name"}
HEALTH_META = {}


def health_once():
    data = SUI.load_all()
    rows = build_relays(data)
    groups = group_rows(rows)
    now = time.time()
    targets = []
    for k, rs in groups.items():
        m = rs[0]
        if k in FO or (POOL.get("auto") or {}).get(k):
            continue  # 有备用落地 / 开了自动换的线路由它们自己的检测负责
        if not m.get("outbound_tag") or not any(r.get("enable") and (not r.get("expiry") or r["expiry"] > now) for r in rs):
            HEALTH.pop(k, None)  # 没有在用的用户：不检测，避免对过期/停用线路误报
            continue
        targets.append((k, m))
    url = CFG.get("check_url")

    def one(item):
        k, m = item
        try:
            r = SUI.check_outbound(m["outbound_tag"], url) or {}
            return k, m, bool(r.get("OK")), r.get("Delay"), r.get("Error") or ""
        except Exception as e:
            return k, m, False, None, str(e)
    with ThreadPoolExecutor(max_workers=8) as ex:
        res = list(ex.map(one, targets))
    need = int(CFG.get("health_fail_times") or 2)
    down, up = [], []
    for k, m, ok, delay, err in res:
        h = HEALTH.setdefault(k, {"fails": 0, "alerted": False})
        h.update(ok=ok, delay=delay, error=err, ts=int(now), landing=m.get("landing"), name=m["tag"])
        if ok:
            if h.get("alerted"):
                up.append(h)
            h["fails"], h["alerted"] = 0, False
        else:
            h["fails"] = h.get("fails", 0) + 1
            if h["fails"] >= need and not h.get("alerted"):
                h["alerted"] = True
                down.append(h)
    for k in list(HEALTH):
        if k not in groups:
            HEALTH.pop(k, None)
    HEALTH_META["last"] = int(now)
    HEALTH_META["count"] = len(targets)
    host = CFG["public_host"]
    if down:
        tg_send("⚠️ 落地不通（%s，%d 条）\n" % (host, len(down)) +
                "\n".join("• %s\n   落地 %s：%s" % (h["name"], h["landing"], (h["error"] or "超时")[:80]) for h in down[:40]) +
                ("\n…还有 %d 条" % (len(down) - 40) if len(down) > 40 else ""))
    if up:
        tg_send("✅ 落地已恢复（%s，%d 条）\n" % (host, len(up)) + "\n".join("• %s（%s，%sms）" % (h["name"], h["landing"], h["delay"]) for h in up[:40]))


def health_loop():
    time.sleep(int(CFG.get("health_first_delay", 30)))
    while True:
        secs = int(CFG.get("health_interval_sec") or 0) or int(CFG.get("health_interval_min") or 0) * 60
        if secs > 0:
            try:
                health_once()
            except Exception as e:
                sys.stderr.write("health: %s\n" % e)
            time.sleep(secs)
        else:
            time.sleep(60)


# ------------------------------------------------------ 备用落地 / 自动切换 --
# 每条线路可以配一个备用落地。线路的出站 tag（= 分组、限额、路由规则用的 key）始终不变，
# 切换时只是把出站的内容换成另一个落地，所以客户链接、流量统计、设备限制都不受影响。
# 另建一个「<tag>-备用落地」出站（不挂任何路由规则）专门放当前没在用的那个落地，用来随时检测它通不通。
FO_PATH = os.path.join(os.path.dirname(CONFIG_PATH), "failover.json")
FO = {}          # okey -> {"primary": ob, "backup": ob, "active": "primary"|"backup", "standby": tag, "auto_back": bool, "switched": ts, "log": [...]}
FO_STATE = {}    # okey -> {"active": 检测结果, "standby": 检测结果, "afails", "sok", "both", "ts"}
FO_LOCK = threading.RLock()
FO_META = {}


def load_fo():
    global FO
    try:
        with open(FO_PATH, encoding="utf-8") as f:
            d = json.load(f)
        FO = d if isinstance(d, dict) else {}
    except Exception:
        FO = {}


def save_fo():
    tmp = FO_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(FO, f, ensure_ascii=False, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, FO_PATH)


def _ob_clean(ob):
    return {k: v for k, v in (ob or {}).items() if k not in ("id", "tag")}


def _ob_addr(ob):
    return "%s:%s" % (ob.get("server", ""), ob.get("server_port", "")) if ob else ""


def _country(ob):
    host = (ob or {}).get("server") or ""
    ip = resolve(host) if host else ""
    return geo_lookup([ip]).get(ip, "") if ip else ""


def _fo_fill_country(f):
    """补上主/备落地的国家（只在缺的时候查一次）。返回是否有改动。"""
    ch = False
    for side, key in (("primary", "pcountry"), ("backup", "bcountry")):
        if f.get(side) and not f.get(key):
            c = _country(f[side])
            if c:
                f[key] = c
                ch = True
    return ch


def _fo_label(f, side):
    c = f.get("pcountry" if side == "primary" else "bcountry") or ""
    return _ob_addr(f.get(side)) + ("（%s）" % c if c else "")


def _write_ob(obs, tag, conf):
    ob = dict(conf)
    ob["tag"] = tag
    cur = obs.get(tag)
    if cur:
        ob["id"] = cur["id"]
        SUI.save("outbounds", "edit", ob)
    else:
        SUI.save("outbounds", "new", ob)


def _fo_swap(okey, to, reason):
    """把线路切到 to（primary / backup）。返回 True 表示切了。"""
    with LOCK, FO_LOCK:
        f = FO.get(okey)
        if not f or f.get("active") == to:
            return False
        obs = {o.get("tag"): o for o in SUI.load_all().get("outbounds") or []}
        if okey not in obs:
            raise SuiError("线路的落地出站不存在")
        other = "primary" if to == "backup" else "backup"
        _write_ob(obs, okey, f[to])              # 在用的出站换成目标落地
        _write_ob(obs, f["standby"], f[other])  # 另一个放进待命出站，继续检测
        f["active"] = to
        f["switched"] = int(time.time())
        f.setdefault("log", []).insert(0, {"ts": f["switched"], "to": to, "reason": reason})
        del f["log"][20:]
        save_fo()
        FO_STATE.pop(okey, None)
        HEALTH.pop(okey, None)
        if not wait_core(6):
            ensure_core()
    return True


def _fo_row(data, tag):
    rows = {r["tag"]: r for r in build_relays(data)}
    row = rows.get(tag)
    if not row or not row.get("outbound_tag"):
        raise SuiError("找不到这条线路的落地出站")
    if row.get("landing_type") == "direct":
        raise SuiError("直连线路没有落地，不能设备用落地")
    return row


def op_failover_set(body):
    """设置 / 修改 / 取消备用落地。landing 为空 = 取消。"""
    data = SUI.load_all()
    row = _fo_row(data, body.get("tag"))
    okey = row["outbound_tag"]
    obs = {o.get("tag"): o for o in data.get("outbounds") or []}
    if body.get("only_flag"):
        with FO_LOCK:
            if okey not in FO:
                raise SuiError("这条线路还没有备用落地")
            FO[okey]["auto_back"] = bool(body.get("auto_back"))
            save_fo()
        return {}
    raw = (body.get("landing") or "").strip()
    if not raw:
        with FO_LOCK:
            if okey not in FO:
                return {"removed": False}
        if FO[okey].get("active") == "backup":
            _fo_swap(okey, "primary", "取消备用落地，切回主落地")
        with LOCK, FO_LOCK:
            try:
                SUI.save("outbounds", "del", FO[okey]["standby"])
            except Exception:
                pass
            FO.pop(okey, None)
            FO_STATE.pop(okey, None)
            save_fo()
        return {"removed": True}
    ob, host, remark = parse_landing(raw)
    ob = _ob_clean(ob)
    with LOCK, FO_LOCK:
        f = FO.get(okey)
        if not f:
            stb = okey + "-备用落地"
            while stb in obs:
                stb += "_"
            f = {"primary": _ob_clean(obs[okey]), "active": "primary", "standby": stb, "log": []}
        if landing_key(ob) == landing_key(f["primary"]):
            raise SuiError("备用落地和主落地是同一个")
        if f.get("backup") and landing_key(f["backup"]) != landing_key(ob):
            f.pop("bcountry", None)
        f["backup"] = ob
        f["auto_back"] = bool(body.get("auto_back", True))
        _fo_fill_country(f)
        if f["active"] == "backup":
            _write_ob(obs, okey, ob)      # 正在用备用：直接换掉在用的出站
        else:
            _write_ob(obs, f["standby"], ob)
        FO[okey] = f
        FO_STATE.pop(okey, None)
        save_fo()
        chk_tag = okey if f["active"] == "backup" else f["standby"]
    chk = op_check({"tags": [chk_tag]})["results"][0]
    return {"check": chk, "backup": _ob_addr(ob)}


def op_failover_switch(body):
    data = SUI.load_all()
    row = _fo_row(data, body.get("tag"))
    to = body.get("to")
    if to not in ("primary", "backup"):
        raise SuiError("参数错误")
    if row["outbound_tag"] not in FO:
        raise SuiError("这条线路还没有备用落地")
    did = _fo_swap(row["outbound_tag"], to, "手动切换")
    return {"switched": did}


def op_failover_status(body):
    """弹窗打开时：立刻检测主备两个落地，并补上国家。"""
    data = SUI.load_all()
    okey = _fo_row(data, body.get("tag"))["outbound_tag"]
    with FO_LOCK:
        f = FO.get(okey)
        if not f:
            raise SuiError("这条线路还没有备用落地")
        f = json.loads(json.dumps(f))
    r = op_check({"tags": [okey, f["standby"]]})["results"]
    now = int(time.time())
    a, sb = dict(r[0], ts=now), dict(r[1], ts=now)
    with FO_LOCK:
        cur = FO.get(okey)
        if cur and cur.get("active") == f["active"]:
            st = FO_STATE.setdefault(okey, {"afails": 0, "sok": 0})
            st.update(active=a, standby=sb, ts=now)
            if _fo_fill_country(cur):
                save_fo()
            f = cur
    return {"active": f["active"], "state": {"active": a, "standby": sb},
            "pcountry": f.get("pcountry", ""), "bcountry": f.get("bcountry", "")}


def fo_summary():
    with FO_LOCK:
        out = {}
        for k, f in FO.items():
            st = FO_STATE.get(k) or {}
            pi, bi = landing_info(f.get("primary") or {}), landing_info(f.get("backup") or {})
            pi["country"], bi["country"] = f.get("pcountry", ""), f.get("bcountry", "")
            out[k] = {"active": f.get("active"), "auto_back": f.get("auto_back", True), "switched": f.get("switched", 0),
                      "primary": pi, "backup": bi, "standby_tag": f.get("standby"),
                      "log": (f.get("log") or [])[:5],
                      "state": {"active": st.get("active"), "standby": st.get("standby"), "ts": st.get("ts", 0)}}
        return out


def failover_once():
    with FO_LOCK:
        items = [(k, json.loads(json.dumps(v))) for k, v in FO.items()]
    if not items:
        return
    data = SUI.load_all()
    obs = {o.get("tag") for o in data.get("outbounds") or []}
    groups = group_rows(build_relays(data))
    url = CFG.get("check_url")

    def chk(tag):
        if tag not in obs:
            return {"ok": False, "error": "出站不存在"}
        try:
            r = SUI.check_outbound(tag, url) or {}
            return {"ok": bool(r.get("OK")), "delay": r.get("Delay"), "error": r.get("Error") or ""}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    jobs = [(k, f) for k, f in items if k in groups]
    with ThreadPoolExecutor(max_workers=8) as ex:
        res = list(ex.map(lambda kf: (kf[0], kf[1], chk(kf[0]), chk(kf[1]["standby"])), jobs))
    need = int(CFG.get("failover_fail_times") or 2)
    back_need = int(CFG.get("failover_back_times") or 3)
    host = CFG["public_host"]
    now = int(time.time())
    for k, f, a, s in res:
        st = FO_STATE.setdefault(k, {"afails": 0, "sok": 0})
        st.update(active=dict(a, ts=now), standby=dict(s, ts=now), ts=now)
        st["afails"] = 0 if a["ok"] else st.get("afails", 0) + 1
        st["sok"] = st.get("sok", 0) + 1 if s["ok"] else 0
        # 检测列显示在用落地的状态
        HEALTH[k] = {"ok": a["ok"], "delay": a.get("delay"), "error": a.get("error"), "fails": st["afails"], "ts": now,
                     "landing": _ob_addr(f.get(f["active"])), "name": groups[k][0]["tag"]}
        name = groups[k][0]["tag"]
        pa, ba = _fo_label(f, "primary"), _fo_label(f, "backup")
        try:
            if a["ok"] and st.get("both"):
                st["both"] = False
                tg_send("✅ %s 落地已恢复（%s）" % (name, host))
            if f["active"] == "primary":
                if st["afails"] >= need and s["ok"]:
                    if _fo_swap(k, "backup", "主落地连续 %d 次不通：%s" % (st["afails"], (a.get("error") or "超时")[:60])):
                        tg_send("🔁 %s 主落地 %s 不通，已自动切到备用落地 %s（%s，客户无需操作）" % (name, pa, ba, host))
                elif st["afails"] >= need and not st.get("both"):
                    st["both"] = True
                    tg_send("⚠️ %s 主落地 %s 和备用落地 %s 都不通（%s）" % (name, pa, ba, host))
            else:
                if f.get("auto_back", True) and st["sok"] >= back_need:
                    if _fo_swap(k, "primary", "主落地已恢复（连续 %d 次检测正常），自动切回" % st["sok"]):
                        tg_send("↩️ %s 主落地 %s 已恢复，已自动切回（%s）" % (name, pa, host))
                elif st["afails"] >= need and s["ok"]:
                    if _fo_swap(k, "primary", "备用落地不通，主落地正常，切回主落地"):
                        tg_send("🔁 %s 备用落地 %s 不通，已切回主落地 %s（%s）" % (name, ba, pa, host))
                elif st["afails"] >= need and not st.get("both"):
                    st["both"] = True
                    tg_send("⚠️ %s 主落地 %s 和备用落地 %s 都不通（%s）" % (name, pa, ba, host))
        except Exception as e:
            sys.stderr.write("failover %s: %s\n" % (k, e))
        with FO_LOCK:
            nf = FO.get(k)
        if nf and nf.get("active") != f["active"]:
            # 刚切换：在用/待命对调，直接用这次的检测结果，不必等下一轮
            FO_STATE[k] = {"active": dict(s, ts=now), "standby": dict(a, ts=now), "afails": 0, "sok": 0, "ts": now, "both": False}
            HEALTH[k] = {"ok": s["ok"], "delay": s.get("delay"), "error": s.get("error"), "fails": 0, "ts": now,
                         "landing": _ob_addr(nf.get(nf["active"])), "name": name}
    FO_META["last"] = now


def failover_loop():
    time.sleep(int(CFG.get("failover_first_delay", 20)))
    while True:
        try:
            failover_once()
        except Exception as e:
            sys.stderr.write("failover: %s\n" % e)
        time.sleep(max(10, int(CFG.get("failover_interval_sec") or 30)))


# ------------------------------------------------------------ 更换链接域名 --
INSTANCE = secrets.token_hex(8)  # 用来确认「新域名访问到的就是这台服务器上的这个程序」
HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")


def _domain_points_here(domain):
    import ssl
    scheme = "https" if CFG.get("cert_file") else "http"
    url = "%s://%s:%s%sapi/whoami" % (scheme, domain, CFG["port"], CFG["path"])
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(url, timeout=8, context=ctx) as r:
            return json.loads(r.read().decode()).get("id") == INSTANCE, ""
    except Exception as e:
        return False, str(e)[:120]


def op_change_domain(body):
    """
    把客户链接里的服务器地址换成新域名：改中转助手的 public_host、s-ui 的面板/订阅域名（如果设置了），
    再重新保存每个用户，让 s-ui 用新域名重新生成链接。客户需要拿新链接。
    """
    domain = (body.get("domain") or "").strip().lower().rstrip(".")
    if not (HOST_RE.match(domain) or is_ip(domain)):
        raise SuiError("域名格式不对")
    old = CFG.get("public_host") or ""
    ip = resolve(domain) or ""
    if not body.get("force"):
        ok, err = _domain_points_here(domain)
        if not ok:
            return {"ok_here": False, "resolved": ip,
                    "error": "通过 %s 访问不到这台服务器上的中转助手（%s 解析到 %s）。请先把域名解析到这台服务器的 IP；"
                             "如果确定已经解析对了（有的云服务器从本机访问不了自己的公网地址），可以强制更换。" % (domain, domain, ip or "无记录")}
    with LOCK:
        st = SUI.get("settings") or {}
        sui_changed = False
        for k in ("webDomain", "subDomain"):
            if st.get(k) and st.get(k) != domain:
                st[k] = domain
                sui_changed = True
        if sui_changed:
            SUI.save("settings", "edit", st)
            subprocess.run(CFG.get("sui_restart_cmd") or "systemctl restart s-ui", shell=True, timeout=90, capture_output=True)
        save_config({"public_host": domain, "sui_host": domain if st.get("webDomain") else ""})
        globals()["SUI"] = Sui(CFG)
        if sui_changed:
            for _ in range(30):  # 等 s-ui 起来
                try:
                    SUI.get("settings")
                    break
                except Exception:
                    time.sleep(1)
        n, errs = 0, []
        for c in SUI.load_all().get("clients") or []:
            try:
                SUI.save("clients", "edit", full_client(c["id"]))  # s-ui 保存用户时按请求的域名重新生成链接
                n += 1
            except Exception as e:
                errs.append("%s：%s" % (c.get("name"), e))
        core = "ok" if wait_core(8) else ensure_core()
    return {"ok_here": True, "old": old, "domain": domain, "clients": n, "errors": errs[:20], "sui_changed": sui_changed,
            "core": core, "https_note": bool(CFG.get("cert_file"))}


def op_whoami(body):
    return {"id": INSTANCE}


# ------------------------------------------------------------- 订阅链接 --
# 每条线路（同一个落地的所有协议节点）一个订阅链接。客户在 v2rayN / Shadowrocket / Clash 里导入一次，
# 之后换端口、换落地、加协议，客户刷新订阅就自动更新。链接里带随机令牌，不需要登录；可以随时重置。
SUBS_PATH = os.path.join(os.path.dirname(CONFIG_PATH), "subs.json")
SUBS = {}  # 线路 key -> 令牌
SUBS_LOCK = threading.Lock()


def load_subs():
    global SUBS
    try:
        with open(SUBS_PATH, encoding="utf-8") as f:
            d = json.load(f)
        SUBS = d if isinstance(d, dict) else {}
    except Exception:
        SUBS = {}


def save_subs():
    tmp = SUBS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(SUBS, f, ensure_ascii=False, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, SUBS_PATH)


def base_url():
    scheme = "https" if CFG.get("cert_file") else "http"
    return "%s://%s:%s%s" % (scheme, CFG["public_host"], CFG["port"], CFG["path"])


def _sub_url(token):
    return base_url() + "sub/" + token


def op_sub_get(body):
    data = SUI.load_all()
    rows = {r["tag"]: r for r in build_relays(data)}
    row = rows.get(body.get("tag"))
    if not row:
        raise SuiError("找不到这条线路")
    k = okey_of(row)
    with SUBS_LOCK:
        if body.get("reset") or k not in SUBS:
            SUBS[k] = secrets.token_urlsafe(18)
            save_subs()
        tok = SUBS[k]
    n = len([r for r in rows.values() if okey_of(r) == k and r.get("client_id")])
    url = _sub_url(tok)
    return {"url": url, "clash": url + "?format=clash", "nodes": n, "svg": qr_svg(url)}


def _sub_links(k):
    """这条线路当前可用的节点链接（停用、过期的不给），以及流量/到期信息。"""
    data = SUI.load_all()
    rs = group_rows(build_relays(data)).get(k) or []
    now = time.time()
    links, up, down, exp = [], 0, 0, 0
    for r in rs:
        up += r.get("up") or 0
        down += r.get("down") or 0
        e = r.get("expiry") or 0
        if e > 0:
            exp = e if not exp else min(exp, e)
        if not r.get("client_id") or not r.get("enable") or (e > 0 and e < now):
            continue
        try:
            links += client_links(r["client_id"])
        except Exception:
            pass
    with LIM_LOCK:
        q = float((LIMITS.get(k) or {}).get("quota_gb") or 0)
    name = re.sub(r"-(HY2|S5|VL|443)(-\d+)?$", "", min((r["tag"] for r in rs), key=len)) if rs else "订阅"
    return links, {"upload": up, "download": down, "total": int(q * 1024 ** 3), "expire": int(exp)}, name


def _v2rayn_link(u):
    """s-ui 的 socks5://账号:密码@主机:端口 换成 v2rayN / Shadowrocket 认的 socks://base64(账号:密码)@主机:端口#名字"""
    if not u.startswith("socks5://"):
        return u
    rest = u[len("socks5://"):]
    cred, _, hp = rest.rpartition("@")
    name = urllib.parse.unquote(cred.split(":", 1)[0])
    b = base64.urlsafe_b64encode(urllib.parse.unquote(cred).encode()).decode().rstrip("=")
    return "socks://%s@%s#%s" % (b, hp.split("#")[0], urllib.parse.quote(name))


def _yq(s):
    return json.dumps(str(s), ensure_ascii=False)  # JSON 字符串就是合法的 YAML 字符串


def _clash_proxy(u):
    p = urllib.parse.urlsplit(u)
    name = urllib.parse.unquote(p.fragment) if p.fragment else ""
    q = dict(urllib.parse.parse_qsl(p.query))
    host, port = p.hostname, p.port
    if p.scheme == "vless":
        name = name or "%s:%s" % (host, port)
        d = [("name", name), ("type", "vless"), ("server", host), ("port", port), ("uuid", urllib.parse.unquote(p.username or "")),
             ("network", q.get("type") or "tcp"), ("udp", True)]
        if q.get("flow"):
            d.append(("flow", q["flow"]))
        if q.get("security") in ("reality", "tls"):
            d += [("tls", True), ("servername", q.get("sni") or host), ("client-fingerprint", q.get("fp") or "chrome")]
            if q.get("security") == "reality":
                d.append(("reality-opts", [("public-key", q.get("pbk", "")), ("short-id", q.get("sid", ""))]))
        return d
    if p.scheme in ("hysteria2", "hy2"):
        name = name or "%s:%s" % (host, port)
        d = [("name", name), ("type", "hysteria2"), ("server", host), ("port", port), ("password", urllib.parse.unquote(p.username or ""))]
        if q.get("sni"):
            d.append(("sni", q["sni"]))
        d.append(("skip-cert-verify", q.get("insecure") == "1"))
        return d
    if p.scheme in ("socks5", "socks"):
        rest = u.split("://", 1)[1]
        cred, _, hp = rest.rpartition("@")
        user, _, pw = urllib.parse.unquote(cred).partition(":")
        name = name or user or "%s:%s" % (host, port)
        return [("name", name), ("type", "socks5"), ("server", host), ("port", port), ("username", user), ("password", pw), ("udp", True)]
    return None


def _yaml_item(d, ind):
    out = []
    for i, (k, v) in enumerate(d):
        pre = (" " * ind + "- ") if i == 0 else (" " * (ind + 2))
        if isinstance(v, list):
            out.append("%s%s:" % (pre, k))
            out += ["%s%s: %s" % (" " * (ind + 4), kk, _yq(vv)) for kk, vv in v]
        elif isinstance(v, bool):
            out.append("%s%s: %s" % (pre, k, "true" if v else "false"))
        elif isinstance(v, int):
            out.append("%s%s: %d" % (pre, k, v))
        else:
            out.append("%s%s: %s" % (pre, k, _yq(v)))
    return out


def clash_yaml(links, title):
    proxies = [x for x in (_clash_proxy(u) for u in links) if x]
    names = [dict(x)["name"] for x in proxies]
    lines = ["# %s（由中转助手生成）" % title, "mixed-port: 7890", "allow-lan: false", "mode: rule", "log-level: info", "", "proxies:"]
    for x in proxies:
        lines += _yaml_item(x, 2)
    if not proxies:
        lines[-1] = "proxies: []"
    lines += ["", "proxy-groups:", "  - name: %s" % _yq("节点选择"), "    type: select", "    proxies:"]
    lines += ["      - %s" % _yq(n) for n in names] + ["      - DIRECT"]
    lines += ["", "rules:", "  - %s" % _yq("MATCH,节点选择"), ""]
    return "\n".join(lines)


def serve_sub(handler, token, query):
    with SUBS_LOCK:
        k = next((kk for kk, t in SUBS.items() if hmac.compare_digest(t, token)), None)
    if not k:
        return handler._send(404, "订阅不存在或已重置", "text/plain; charset=utf-8")
    try:
        links, info, name = _sub_links(k)
    except Exception as e:
        return handler._send(503, "暂时无法获取节点：%s" % e, "text/plain; charset=utf-8")
    ua = (handler.headers.get("User-Agent") or "").lower()
    fmt = (urllib.parse.parse_qs(query).get("format") or [""])[0].lower()
    if not fmt:
        fmt = "clash" if any(x in ua for x in ("clash", "mihomo", "stash", "meta")) else "base64"
    hdr = {"Subscription-Userinfo": "; ".join("%s=%d" % kv for kv in info.items() if kv[0] != "total" or kv[1]),
           "Profile-Update-Interval": "6",
           "Content-Disposition": "attachment; filename*=UTF-8''%s" % urllib.parse.quote(name),
           "Profile-Title": "base64:" + base64.b64encode(name.encode()).decode()}
    if fmt == "clash":
        body = clash_yaml(links, name)
        return handler._send(200, body, "text/yaml; charset=utf-8", headers=hdr)
    body = base64.b64encode("\n".join(_v2rayn_link(u) for u in links).encode()).decode()
    return handler._send(200, body, "text/plain; charset=utf-8", headers=hdr)


# ------------------------------------------------------------ 多服务器 --
# 每台服务器照常装中转助手；在其中一台（主控）里添加其他服务器的地址和「连接密钥」，
# 主控把页面上的操作转发给选中的服务器。连接密钥 = 对方中转助手配置里的 api_token。
SERVERS_PATH = os.path.join(os.path.dirname(CONFIG_PATH), "servers.json")
SERVERS = []
SRV_LOCK = threading.Lock()
LOCAL_ONLY = {"login", "logout", "servers_list", "server_save", "server_del", "servers_overview", "local_token_reset"}


def load_servers():
    global SERVERS
    try:
        with open(SERVERS_PATH, encoding="utf-8") as f:
            d = json.load(f)
        SERVERS = d if isinstance(d, list) else []
    except Exception:
        SERVERS = []


def save_servers():
    tmp = SERVERS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(SERVERS, f, ensure_ascii=False, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, SERVERS_PATH)


def _server(sid):
    with SRV_LOCK:
        sv = next((s for s in SERVERS if s.get("id") == sid), None)
    if not sv:
        raise SuiError("没有这台服务器（可能已被删除），请在顶部重新选择")
    return sv


def _remote(sv, path, data=None, headers=None, timeout=120, method=None):
    import ssl
    h = {"X-RH-Token": sv.get("token", ""), "User-Agent": "relay-helper/%s" % VERSION}
    h.update(headers or {})
    req = urllib.request.Request(sv["url"] + path, data=data, headers=h, method=method)
    hs = [urllib.request.ProxyHandler({})]
    if sv.get("insecure"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        hs.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*hs).open(req, timeout=timeout)


def proxy_json(sid, action, body, timeout=120):
    try:
        sv = _server(sid)
    except SuiError as e:
        return {"ok": False, "error": str(e)}
    name = sv.get("name") or sv["url"]
    try:
        with _remote(sv, "api/" + action, json.dumps(body or {}).encode(), {"Content-Type": "application/json"}, timeout) as r:
            res = json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            res = json.loads(e.read().decode("utf-8") or "{}")
        except Exception:
            return {"ok": False, "error": "服务器「%s」返回 HTTP %s（检查地址是不是对方中转助手的完整地址，含路径）" % (name, e.code)}
    except Exception as e:
        msg = str(getattr(e, "reason", e))
        if "CERTIFICATE" in msg.upper():
            msg += "（对方用的是自签名证书的话，编辑这台服务器勾选「忽略证书校验」）"
        return {"ok": False, "error": "连不上服务器「%s」：%s" % (name, msg)}
    if isinstance(res, dict) and res.get("login"):
        return {"ok": False, "error": "服务器「%s」的连接密钥不对（在那台服务器的「服务器」页复制本机连接密钥）" % name}
    return res


def _norm_url(u):
    u = (u or "").strip()
    if not re.match(r"^https?://[^/\s]+", u):
        raise SuiError("地址要以 http:// 或 https:// 开头，例如 https://hk2.example.com:2097/kaide/")
    u = u.split("#", 1)[0].split("?", 1)[0]
    if "/api/" in u:
        u = u.split("/api/", 1)[0]
    return u.rstrip("/") + "/"


def op_ping(body):
    return {"version": VERSION, "public_host": CFG.get("public_host")}


def op_servers_list(body):
    with SRV_LOCK:
        lst = [{"id": s["id"], "name": s.get("name", ""), "url": s["url"], "insecure": bool(s.get("insecure"))} for s in SERVERS]
    return {"servers": lst, "local": {"public_host": CFG.get("public_host"), "url": base_url(), "token": CFG.get("api_token", "")}}


def op_server_save(body):
    url = _norm_url(body.get("url"))
    sid = body.get("id") or secrets.token_hex(4)
    with SRV_LOCK:
        old = next((s for s in SERVERS if s.get("id") == sid), None)
    token = (body.get("token") or "").strip() or (old or {}).get("token", "")
    if not token:
        raise SuiError("请填写对方的连接密钥")
    sv = {"id": sid, "name": (body.get("name") or "").strip() or urllib.parse.urlsplit(url).hostname, "url": url,
          "token": token, "insecure": bool(body.get("insecure"))}
    if url.rstrip("/") == base_url().rstrip("/"):
        raise SuiError("这是本机的地址，不用添加")
    with SRV_LOCK:
        dup = next((s for s in SERVERS if s.get("url") == url and s.get("id") != sid), None)
    if dup:
        raise SuiError("这个地址已经添加过了（「%s」）" % dup.get("name"))
    # 先试连
    with SRV_LOCK:
        tmp = [s for s in SERVERS if s.get("id") != sid] + [sv]
        bak = list(SERVERS)
        SERVERS[:] = tmp
    res = proxy_json(sid, "ping", {}, timeout=15)
    if not res.get("ok"):
        with SRV_LOCK:
            SERVERS[:] = bak
        raise SuiError(res.get("error") or "连接失败")
    with SRV_LOCK:
        save_servers()
    return {"id": sid, "remote": {"version": res.get("version"), "public_host": res.get("public_host")}}


def op_server_del(body):
    with SRV_LOCK:
        SERVERS[:] = [s for s in SERVERS if s.get("id") != body.get("id")]
        save_servers()
    return {}


def op_local_token_reset(body):
    save_config({"api_token": secrets.token_urlsafe(24)})
    return {"token": CFG["api_token"]}


def _summary(res):
    if not res.get("ok"):
        return {"ok": False, "error": res.get("error", "")}
    rows, now = res.get("relays") or [], res.get("now") or time.time()
    groups = {}
    for r in rows:
        groups.setdefault(r.get("outbound_tag") or "#" + r["tag"], []).append(r)
    soon = expired = 0
    for g in groups.values():
        ex = [r.get("expiry") or 0 for r in g if r.get("client_id")]
        if ex and all(0 < e < now for e in ex):
            expired += 1
        elif any(now < e < now + 7 * 86400 for e in ex):
            soon += 1
    bad = sum(1 for h in (res.get("health") or {}).values() if h and h.get("ok") is False)
    return {"ok": True, "public_host": res.get("public_host"), "version": res.get("version"), "lines": len(groups),
            "nodes": len(rows), "soon": soon, "expired": expired, "bad": bad,
            "rows": [{"tag": r["tag"], "landing": r.get("landing") or "", "expiry": r.get("expiry") or 0, "enable": r.get("enable")} for r in rows]}


def op_servers_overview(body):
    with SRV_LOCK:
        lst = list(SERVERS)
    out = [dict(_summary(dict(op_list({}), ok=True)), id="local", name="本机", url=base_url())]
    with ThreadPoolExecutor(max_workers=8) as ex:
        res = list(ex.map(lambda s: (s, proxy_json(s["id"], "list", {}, timeout=25)), lst))
    for s, r in res:
        out.append(dict(_summary(r), id=s["id"], name=s.get("name", ""), url=s["url"]))
    return {"servers": out}


# ------------------------------------------------------------- 落地库 --
# 把买来的落地统一存起来：国家、网段、供应商、进价、落地到期、检测结果；是否在用、被哪条线路用，按出站实时算。
# 线路可以一键从库里换一个（同国家、优先不同网段——同网段的 IP 常常一起出问题），也可以开「自动换」：
# 落地连续不通就自动换成库里能用的，线路的出站名不变，所以客户链接、订阅、限额都不变。
POOL_PATH = os.path.join(os.path.dirname(CONFIG_PATH), "landings.json")
POOL = {"items": [], "auto": {}}
POOL_LOCK = threading.RLock()
POOL_STATE = {}  # 线路 key -> {"fails", "last_switch", "noalert"}


def load_pool():
    global POOL
    try:
        with open(POOL_PATH, encoding="utf-8") as f:
            d = json.load(f)
        POOL = d if isinstance(d, dict) else {}
    except Exception:
        POOL = {}
    POOL.setdefault("items", [])
    POOL.setdefault("auto", {})


def save_pool():
    tmp = POOL_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(POOL, f, ensure_ascii=False, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, POOL_PATH)


def ip_net(ip):
    """网段：IPv4 取 /24，IPv6 取 /48。"""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    return str(ipaddress.ip_network("%s/%d" % (ip, 24 if a.version == 4 else 48), strict=False))


def _pool_usage(data=None):
    """落地 key -> [使用它的线路名（备用的标「备用」）]"""
    data = data or SUI.load_all()
    obs = {o.get("tag"): o for o in data.get("outbounds") or []}
    use = {}
    for k, rs in group_rows(build_relays(data)).items():
        ob = obs.get(k)
        if not ob or ob.get("type") == "direct":
            continue
        name = min((r["tag"] for r in rs), key=len)
        use.setdefault(landing_key(ob), []).append(name)
    with FO_LOCK:
        for k, f in FO.items():
            other = "backup" if f.get("active") == "primary" else "primary"
            if f.get(other):
                use.setdefault(landing_key(f[other]), []).append("%s（备用）" % k)
    return use


def _rec_public(it, use, now):
    r = {k: it.get(k) for k in ("id", "raw", "host", "ip", "port", "type", "country", "net", "supplier", "cost", "expire", "note", "disabled", "added", "check")}
    r["used_by"] = use.get(landing_key(it["ob"]), [])
    r["expired"] = bool(it.get("expire") and it["expire"] < now)
    r["info"] = landing_info(it["ob"])
    return r


def op_pool_list(body):
    data = SUI.load_all()
    use = _pool_usage(data)
    now = time.time()
    with POOL_LOCK:
        items = [_rec_public(it, use, now) for it in POOL["items"]]
        auto = dict(POOL["auto"])
    groups = group_rows(build_relays(data))
    return {"items": items, "auto": [k for k, v in auto.items() if v and k in groups], "now": now}


def op_pool_import(body):
    lines = [l.strip() for l in (body.get("text") or "").splitlines() if l.strip()]
    if not lines:
        raise SuiError("没有内容")
    parsed, errors = [], []
    for ln in lines:
        try:
            ob, host, remark = parse_landing(ln)
            if ob.get("type") == "direct":
                raise ValueError("直连不能放进落地库")
            parsed.append((ln, ob, host))
        except Exception as e:
            errors.append({"line": ln, "error": str(e)})
    ips = {h: resolve(h) for _, _, h in parsed}
    geo = geo_lookup([ip for ip in ips.values() if ip])
    exp = int(body.get("expire") or 0)
    added, dup = 0, 0
    with POOL_LOCK:
        have = {landing_key(it["ob"]) for it in POOL["items"]}
        for ln, ob, host in parsed:
            k = landing_key(ob)
            if k in have:
                dup += 1
                continue
            have.add(k)
            ip = ips.get(host) or ""
            POOL["items"].append({"id": secrets.token_hex(5), "raw": ln, "ob": ob, "host": host, "ip": ip,
                                  "port": ob.get("server_port"), "type": ob.get("type"),
                                  "country": (body.get("country") or "").strip() or geo.get(ip, ""), "net": ip_net(ip),
                                  "supplier": (body.get("supplier") or "").strip(), "cost": (body.get("cost") or "").strip(),
                                  "expire": exp, "note": (body.get("note") or "").strip(), "disabled": False,
                                  "added": int(time.time()), "check": None})
            added += 1
        save_pool()
    return {"added": added, "dup": dup, "errors": errors}


def op_pool_update(body):
    ids = set(body.get("ids") or [])
    fields = {k: body[k] for k in ("supplier", "cost", "expire", "note", "country", "disabled") if k in body}
    if "expire" in fields:
        fields["expire"] = int(fields["expire"] or 0)
    if "disabled" in fields:
        fields["disabled"] = bool(fields["disabled"])
    with POOL_LOCK:
        n = 0
        for it in POOL["items"]:
            if it["id"] in ids:
                it.update(fields)
                n += 1
        save_pool()
    return {"updated": n}


def op_pool_delete(body):
    ids = set(body.get("ids") or [])
    with POOL_LOCK:
        before = len(POOL["items"])
        POOL["items"] = [it for it in POOL["items"] if it["id"] not in ids]
        save_pool()
        return {"deleted": before - len(POOL["items"])}


def _pool_check_items(items):
    """检测落地库里的落地（临时出站），结果写回记录。"""
    res = op_check_raw({"items": [{"raw": it["id"], "outbound": it["ob"]} for it in items]})["results"]
    now = int(time.time())
    by = {r["raw"]: r for r in res}
    with POOL_LOCK:
        for it in POOL["items"]:
            r = by.get(it["id"])
            if r:
                it["check"] = {"ok": r["ok"], "delay": r.get("delay"), "error": (r.get("error") or "")[:160], "ts": now}
        save_pool()
    return by


def op_pool_check(body):
    ids = set(body.get("ids") or [])
    with POOL_LOCK:
        items = [dict(it) for it in POOL["items"] if it["id"] in ids][:60]
    by = _pool_check_items(items)
    return {"results": [{"id": i, "ok": r["ok"], "delay": r.get("delay"), "error": r.get("error", "")} for i, r in by.items()]}


def _line(tag, data):
    rows = {r["tag"]: r for r in build_relays(data)}
    row = rows.get(tag)
    if not row or not row.get("outbound_tag"):
        raise SuiError("找不到这条线路的落地出站")
    if row.get("landing_type") == "direct":
        raise SuiError("直连线路没有落地")
    return row


def _current(okey, data):
    obs = {o.get("tag"): o for o in data.get("outbounds") or []}
    ob = obs.get(okey) or {}
    ip = resolve(ob.get("server", "")) if ob else ""
    k = landing_key(ob) if ob else ""
    with POOL_LOCK:
        rec = next((it for it in POOL["items"] if landing_key(it["ob"]) == k), None)
    country = (rec or {}).get("country") or (geo_lookup([ip]).get(ip, "") if ip else "")
    return {"ob": ob, "ip": ip, "net": ip_net(ip), "country": country, "rec_id": (rec or {}).get("id"),
            "addr": "%s:%s" % (ob.get("server", ""), ob.get("server_port", ""))}


def _candidates(cur, use, country=None):
    """只挑同国家、没停用、没到期的落地（可以和别的线路共用），
    排序：同网段优先 → 最近没失败 → 检测能通 → 在用的线路少 → 延迟低。"""
    country = cur.get("country") or ""
    now = time.time()
    with POOL_LOCK:
        items = [dict(it) for it in POOL["items"]]
    out = []
    for it in items:
        if it.get("disabled") or (it.get("expire") and it["expire"] < now):
            continue
        if cur.get("ob") and landing_key(it["ob"]) == landing_key(cur["ob"]):
            continue  # 就是现在用的这个
        if (it.get("country") or "") != country:
            continue  # 只换同国家的（当前落地国家未知时，只在国家同样未知的里挑）
        if it.get("id") == cur.get("rec_id"):
            continue
        c = it.get("check") or {}
        recent_fail = bool(c) and not c.get("ok") and now - (c.get("ts") or 0) < 600
        same_net = bool(cur.get("net")) and it.get("net") == cur["net"]
        n_use = len([u for u in use.get(landing_key(it["ob"]), []) if not u.endswith("（备用）")])
        score = (not same_net, recent_fail, not c.get("ok"), n_use, c.get("delay") or 99999)
        out.append((score, it))
    out.sort(key=lambda x: x[0])
    return [it for _, it in out]


def op_pool_candidates(body):
    data = SUI.load_all()
    row = _line(body.get("tag"), data)
    k = row["outbound_tag"]
    cur = _current(k, data)
    use = _pool_usage(data)
    cands = _candidates(cur, use, body.get("country"))
    now = time.time()
    with POOL_LOCK:
        countries = sorted({it.get("country") or "" for it in POOL["items"]} - {""})
        auto = bool(POOL["auto"].get(k))
    return {"current": {"addr": cur["addr"], "country": cur["country"], "net": cur["net"], "in_pool": bool(cur["rec_id"])},
            "auto": auto, "has_failover": k in FO, "countries": countries,
            "candidates": [_rec_public(it, use, now) for it in cands[:30]]}


def _switch_to(row, it, reason):
    """把线路的落地原位换成落地库里的 it（出站名不变）。"""
    ob = dict(it["ob"])
    res = op_replace({"tag": row["tag"], "outbound": ob})
    return res


def op_pool_switch(body):
    """手动：指定 id 换；不指定就自动挑（会先检测，挑第一个能通的）。"""
    data = SUI.load_all()
    row = _line(body.get("tag"), data)
    if body.get("id"):
        with POOL_LOCK:
            it = next((dict(x) for x in POOL["items"] if x["id"] == body["id"]), None)
        if not it:
            raise SuiError("落地库里没有这个落地")
        cur = _current(row["outbound_tag"], data)
    else:
        cur = _current(row["outbound_tag"], data)
        it = _pick_working(cur, _pool_usage(data), body.get("country"))
        if not it:
            raise SuiError("落地库里没有能用的%s落地（没停用、没到期、检测能通）" % (cur["country"] or "同国家"))
    res = _switch_to(row, it, "手动")
    return {"from": cur["addr"], "to": "%s:%s" % (it["host"], it["port"]), "country": it.get("country"), "net": it.get("net"),
            "same_net": bool(cur["net"]) and cur["net"] == it.get("net"), "check": res.get("check")}


def _pick_working(cur, use, country=None):
    cands = _candidates(cur, use, country)
    for i in range(0, min(len(cands), 9), 3):  # 每次检测 3 个，最多 9 个
        batch = cands[i:i + 3]
        by = _pool_check_items(batch)
        for it in batch:
            if (by.get(it["id"]) or {}).get("ok"):
                return it
    return None


def op_pool_auto(body):
    data = SUI.load_all()
    on = bool(body.get("on"))
    rows = {r["tag"]: r for r in build_relays(data)}
    n = 0
    with POOL_LOCK:
        for t in body.get("tags") or []:
            r = rows.get(t)
            if r and r.get("outbound_tag") and r.get("landing_type") != "direct":
                if on:
                    POOL["auto"][r["outbound_tag"]] = True
                else:
                    POOL["auto"].pop(r["outbound_tag"], None)
                n += 1
        save_pool()
    return {"updated": n}


def pool_once():
    with POOL_LOCK:
        auto = [k for k, v in POOL["auto"].items() if v]
    if not auto:
        return
    data = SUI.load_all()
    groups = group_rows(build_relays(data))
    keys = [k for k in auto if k in groups and k not in FO and any(r.get("enable") and r.get("client_id") for r in groups[k])]
    if not keys:
        return
    res = op_check({"tags": keys})["results"]
    need = int(CFG.get("pool_fail_times") or 2)
    now = time.time()
    use = None
    for r in res:
        k = r["tag"]
        st = POOL_STATE.setdefault(k, {"fails": 0, "last_switch": 0, "noalert": False})
        HEALTH[k] = {"ok": r["ok"], "delay": r.get("delay"), "error": r.get("error"), "fails": 0 if r["ok"] else st["fails"] + 1,
                     "ts": int(now), "landing": "", "name": groups[k][0]["tag"]}
        if r["ok"]:
            st["fails"], st["noalert"] = 0, False
            continue
        st["fails"] += 1
        if st["fails"] < need or now - st["last_switch"] < 90:  # 刚换过的给 90 秒稳定时间，避免来回切
            continue
        name = min((x["tag"] for x in groups[k]), key=len)
        try:
            use = use or _pool_usage(data)
            cur = _current(k, data)
            # 当前落地记为失败
            if cur["rec_id"]:
                with POOL_LOCK:
                    for it in POOL["items"]:
                        if it["id"] == cur["rec_id"]:
                            it["check"] = {"ok": False, "delay": None, "error": (r.get("error") or "")[:160], "ts": int(now)}
                    save_pool()
            it = _pick_working(cur, use)
            if not it:
                if not st["noalert"]:
                    tg_send("⚠️ %s 落地 %s（%s）不通，落地库里没有能用的同国家落地可换（%s）" % (name, cur["addr"], cur["country"] or "?", CFG["public_host"]))
                    st["noalert"] = True
                continue
            _switch_to(groups[k][0], it, "自动")
            use = None
            st.update(fails=0, last_switch=now, noalert=False)
            tg_send("🔁 %s 落地 %s（%s %s）不通，已自动换成落地库里的 %s:%s（%s）。客户链接不变（%s）" % (
                name, cur["addr"], cur["country"], cur["net"], it["host"], it["port"], it.get("net") or "", CFG["public_host"]))
        except Exception as e:
            sys.stderr.write("pool switch %s: %s\n" % (k, e))


def pool_loop():
    time.sleep(25)
    while True:
        try:
            pool_once()
        except Exception as e:
            sys.stderr.write("pool: %s\n" % e)
        time.sleep(max(20, int(CFG.get("pool_interval_sec") or 60)))


# ---------------------------------------------------------------- 备份/恢复 --
# 和 s-ui 自带的「下载备份 / 恢复备份」一样：下载时现做一份发给浏览器（服务器上不留），恢复时上传文件。
# 换服务器：旧机下载备份 → 域名解析到新机 → 新机装好 s-ui + 中转助手 → 上传恢复，节点/用户/到期/限额/证书全部带过去。
RESTORE_MAX = 2 * 1024 * 1024 * 1024
SUI_FILE_SETTINGS = ("webCertFile", "webKeyFile", "subCertFile", "subKeyFile")


def _ref_files(dbpath):
    """数据库里引用到的证书文件（TLS 设置里的 certificate_path/key_path、面板/订阅证书）。"""
    out = set()
    c = sqlite3.connect(dbpath)
    try:
        try:
            for (srv,) in c.execute("select server from tls"):
                try:
                    j = json.loads(srv.decode() if isinstance(srv, bytes) else (srv or "{}"))
                except ValueError:
                    continue
                for k in ("certificate_path", "key_path"):
                    if isinstance(j.get(k), str) and j[k].startswith("/"):
                        out.add(j[k])
        except sqlite3.Error:
            pass
        try:
            for k, v in c.execute("select key, value from settings"):
                v = v.decode() if isinstance(v, bytes) else v
                if k in SUI_FILE_SETTINGS and isinstance(v, str) and v.startswith("/"):
                    out.add(v)
        except sqlite3.Error:
            pass
    finally:
        c.close()
    return sorted(out)


def make_backup(full=False, out=None):
    """生成备份文件，返回 (路径, 下载文件名)。"""
    import tarfile, tempfile
    db = CFG.get("sui_db")
    if not db or not os.path.exists(db):
        raise SuiError("找不到 s-ui 数据库：%s（配置项 sui_db）" % db)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    host = re.sub(r"[^0-9A-Za-z.-]", "_", CFG.get("public_host") or "server")
    name = "relay-backup-%s-%s.tar.gz" % (host, stamp)
    if not out:
        fd, out = tempfile.mkstemp(prefix="rh-backup-", suffix=".tar.gz", dir=os.path.dirname(CONFIG_PATH))
        os.close(fd)
    with tempfile.TemporaryDirectory(dir=os.path.dirname(CONFIG_PATH)) as td:
        snap = os.path.join(td, "s-ui.db")
        src = sqlite3.connect("file:%s?mode=ro" % db, uri=True, timeout=30)
        dst = sqlite3.connect(snap)
        with dst:
            src.backup(dst)  # 在线一致性快照，s-ui 运行中也安全
        src.close()
        if not full:
            # 默认不带流量统计历史（stats，每 10 秒每个节点一条，可达上百 MB）和操作记录（changes）：
            # 只用于 s-ui 面板画曲线；每个用户的累计流量在 clients 表里，照常备份
            for tb in ("stats", "changes"):
                try:
                    dst.execute('DELETE FROM "%s"' % tb)
                except sqlite3.Error:
                    pass
            dst.commit()
            dst.execute("VACUUM")
        dst.close()
        files = [f for f in _ref_files(snap) if os.path.isfile(f) and os.path.getsize(f) < 1024 * 1024]
        meta = os.path.join(td, "backup-info.json")
        with open(meta, "w", encoding="utf-8") as f:
            json.dump({"time": stamp, "host": CFG.get("public_host"), "version": VERSION, "full": bool(full), "files": files},
                      f, ensure_ascii=False)
        st = os.path.join(td, "relay-helper-settings.json")
        with open(st, "w", encoding="utf-8") as f:
            json.dump({k: CFG.get(k) for k in SETTING_KEYS}, f, ensure_ascii=False)
        with tarfile.open(out, "w:gz") as tar:
            tar.add(snap, "s-ui.db")
            tar.add(meta, "backup-info.json")
            tar.add(st, "relay-helper-settings.json")
            if os.path.exists(LIMITS_PATH):
                tar.add(LIMITS_PATH, "limits.json")
            if os.path.exists(FO_PATH):
                tar.add(FO_PATH, "failover.json")
            if os.path.exists(SUBS_PATH):
                tar.add(SUBS_PATH, "subs.json")
            if os.path.exists(SERVERS_PATH):
                tar.add(SERVERS_PATH, "servers.json")
            if os.path.exists(POOL_PATH):
                tar.add(POOL_PATH, "landings.json")
            for fp in files:
                tar.add(fp, "files" + fp)
    os.chmod(out, 0o600)
    return out, name


def _sui_conn_from_db(dbpath):
    """从（恢复后的）s-ui 数据库读面板端口/路径/管理员账号，算出中转助手连接 s-ui 要用的配置。"""
    c = sqlite3.connect("file:%s?mode=ro" % dbpath, uri=True)
    try:
        st = {k: (v.decode() if isinstance(v, bytes) else v) for k, v in c.execute("select key, value from settings")}
        users = list(c.execute("select username, password from users order by id"))
    finally:
        c.close()
    up = {}
    if users and users[0][0] and users[0][1]:
        up["sui_user"], up["sui_pass"] = users[0][0], users[0][1]
    web_path = st.get("webPath") or "/app/"
    web_path = ("/" + web_path.strip("/") + "/") if web_path.strip("/") else "/"
    listen = st.get("webListen") or "127.0.0.1"
    if listen in ("0.0.0.0", "::", ""):
        listen = "127.0.0.1"
    scheme = "https" if st.get("webCertFile") and st.get("webKeyFile") else "http"
    up["sui_url"] = "%s://%s:%s%s" % (scheme, listen, st.get("webPort") or "2095", web_path)
    up["sui_host"] = st.get("webDomain") or ""
    return up


def restore_file(path):
    import tarfile, tempfile
    with open(path, "rb") as f:
        head = f.read(16)
    db = CFG.get("sui_db")
    warnings = []
    with tempfile.TemporaryDirectory(dir=os.path.dirname(CONFIG_PATH)) as td:
        snap = os.path.join(td, "s-ui.db")
        files, limits, settings, info = [], None, None, {}
        if head.startswith(b"SQLite format 3"):
            shutil.copyfile(path, snap)  # s-ui 面板自己「下载备份」得到的 .db 文件也能直接恢复
            info = {"source": "s-ui"}
        elif head[:2] == b"\x1f\x8b":
            try:
                with tarfile.open(path, "r:gz") as tar:
                    for m in tar.getmembers():
                        nm = m.name
                        if not m.isfile() or ".." in nm.split("/") or nm.startswith("/"):
                            continue
                        if nm in ("s-ui.db", "limits.json", "failover.json", "subs.json", "servers.json", "landings.json", "relay-helper-settings.json", "backup-info.json") or \
                                (nm.startswith("files/") and m.size < 1024 * 1024):
                            dest = os.path.join(td, "x", nm)
                            os.makedirs(os.path.dirname(dest), exist_ok=True)
                            with tar.extractfile(m) as fi, open(dest, "wb") as fo:
                                shutil.copyfileobj(fi, fo)
                            if nm == "s-ui.db":
                                os.replace(dest, snap)
                            elif nm.startswith("files/"):
                                files.append((nm[len("files"):], dest))
            except (tarfile.TarError, OSError, EOFError) as e:
                raise SuiError("备份文件损坏：%s" % e)
            x = os.path.join(td, "x")
            for nm, var in (("limits.json", "limits"), ("relay-helper-settings.json", "settings"), ("backup-info.json", "info")):
                fp = os.path.join(x, nm)
                if os.path.exists(fp):
                    try:
                        with open(fp, encoding="utf-8") as f:
                            val = json.load(f)
                    except ValueError:
                        continue
                    if var == "limits":
                        limits = fp
                    elif var == "settings":
                        settings = val
                    else:
                        info = val
        else:
            raise SuiError("不是备份文件（请上传中转助手下载的 .tar.gz，或 s-ui 面板下载的 .db）")
        if not os.path.exists(snap):
            raise SuiError("备份里没有 s-ui 数据库")
        try:
            c = sqlite3.connect(snap)
            ok = c.execute("pragma integrity_check").fetchone()[0]
            tables = {r[0] for r in c.execute("select name from sqlite_master where type='table'")}
            n_in = c.execute("select count(*) from inbounds").fetchone()[0] if "inbounds" in tables else 0
            n_cl = c.execute("select count(*) from clients").fetchone()[0] if "clients" in tables else 0
            c.close()
        except sqlite3.Error as e:
            raise SuiError("备份里的数据库打不开：%s" % e)
        if ok != "ok":
            raise SuiError("备份里的数据库校验失败：%s" % ok)
        if not {"inbounds", "settings", "users"} <= tables:
            raise SuiError("这不是 s-ui 的数据库")

        with LOCK:
            before = os.path.join(os.path.dirname(CONFIG_PATH), "before-restore.tar.gz")
            try:
                make_backup(False, out=before)  # 恢复前把当前状态留一份，恢复错了还能救回来
            except Exception as e:
                warnings.append("恢复前没能保存当前状态：%s" % e)
                before = ""
            subprocess.run(CFG.get("sui_stop_cmd") or "systemctl stop s-ui", shell=True, timeout=60, capture_output=True)
            time.sleep(1)
            for ext in ("-wal", "-shm"):
                try:
                    os.remove(db + ext)
                except OSError:
                    pass
            shutil.copyfile(snap, db + ".restore")
            os.replace(db + ".restore", db)
            # 证书文件：新服务器上没有的才写入，已有的不覆盖
            for dst, src in files:
                if not os.path.exists(dst):
                    try:
                        os.makedirs(os.path.dirname(dst), exist_ok=True)
                        shutil.copyfile(src, dst)
                        os.chmod(dst, 0o600)
                    except OSError as e:
                        warnings.append("证书文件 %s 写入失败：%s" % (dst, e))
            for fp in _ref_files(db):
                if not os.path.exists(fp):
                    warnings.append("s-ui 用到的证书文件 %s 在这台服务器上不存在，相关节点/面板可能起不来" % fp)
            if limits:
                shutil.copyfile(limits, LIMITS_PATH)
            fo = os.path.join(td, "x", "failover.json")
            if os.path.exists(fo):
                shutil.copyfile(fo, FO_PATH)
            else:  # 备份里没有备用落地记录（s-ui 的 .db 或旧版本备份）：清空，免得和恢复后的出站对不上
                with FO_LOCK:
                    FO.clear()
                    save_fo()
            with FO_LOCK:
                load_fo()
                FO_STATE.clear()
            sb = os.path.join(td, "x", "subs.json")
            if os.path.exists(sb):
                shutil.copyfile(sb, SUBS_PATH)
            with SUBS_LOCK:
                load_subs()
            lp = os.path.join(td, "x", "landings.json")
            if os.path.exists(lp):
                shutil.copyfile(lp, POOL_PATH)
                with POOL_LOCK:
                    load_pool()
            sv = os.path.join(td, "x", "servers.json")
            if os.path.exists(sv):
                shutil.copyfile(sv, SERVERS_PATH)
                with SRV_LOCK:
                    load_servers()
            up = _sui_conn_from_db(db)
            if isinstance(settings, dict):
                for k in SETTING_KEYS:
                    if k in settings and settings[k] not in (None, ""):
                        up[k] = settings[k]
            save_config(up)
            with LIM_LOCK:
                load_limits()
            HEALTH.clear()
            subprocess.run(CFG.get("sui_start_cmd") or "systemctl start s-ui", shell=True, timeout=60, capture_output=True)
            global SUI
            SUI = Sui(CFG)
            deadline = time.time() + 40
            time.sleep(2)
            core = "down"
            while time.time() < deadline:
                try:
                    if core_running():
                        core = "ok"
                        break
                except Exception:
                    pass
                time.sleep(1)
            ports = 0
            try:
                reserve_ports()
                for ib in SUI.load_all().get("inbounds") or []:
                    if str(ib.get("listen_port") or "").isdigit():
                        open_firewall(int(ib["listen_port"]), ib.get("type") in ("hysteria2", "hysteria", "tuic"))
                        ports += 1
            except Exception as e:
                warnings.append("恢复后连接 s-ui 失败：%s" % e)
    return {"core": core, "inbounds": n_in, "clients": n_cl, "from_host": info.get("host") or info.get("source") or "",
            "backup_time": info.get("time", ""), "before": before, "warnings": warnings}


OPS.update({"set_limits": op_set_limits, "reset_traffic": op_reset_traffic, "kick": op_kick, "get_settings": op_get_settings, "save_settings": op_save_settings, "tg_test": op_tg_test, "failover_set": op_failover_set, "failover_switch": op_failover_switch, "failover_status": op_failover_status, "change_port": op_change_port, "change_domain": op_change_domain, "sub_get": op_sub_get, "ping": op_ping, "servers_list": op_servers_list,
            "server_save": op_server_save, "server_del": op_server_del, "servers_overview": op_servers_overview,
            "local_token_reset": op_local_token_reset, "pool_list": op_pool_list, "pool_import": op_pool_import,
            "pool_update": op_pool_update, "pool_delete": op_pool_delete, "pool_check": op_pool_check,
            "pool_candidates": op_pool_candidates, "pool_switch": op_pool_switch, "pool_auto": op_pool_auto})


# ------------------------------------------------------------- web server --
SESSIONS = {}
FAILS = {}
SESSION_AGE = 7 * 86400


def check_password(p):
    return hmac.compare_digest(hashlib.sha256((p or "").encode()).digest(),
                               hashlib.sha256(CFG["password"].encode()).digest()) and bool(CFG["password"])


LOGIN_ERR = {"detail": ""}


def check_sui_login(user, pw):
    """
    用 s-ui 的账号密码登录：每次都拿去问 s-ui，所以在 s-ui 里改了密码这里自动跟着变。
    返回 True / False；s-ui 连不上时返回 None。
    """
    if not user or not pw:
        return False
    LOGIN_ERR["detail"] = ""
    try:
        Sui(dict(CFG, sui_user=user, sui_pass=pw)).login()
    except SuiError as e:
        if "连接 s-ui 失败" in str(e):
            LOGIN_ERR["detail"] = str(e)
            return None
        return False
    except Exception as e:
        LOGIN_ERR["detail"] = "%s %s（地址 %s）" % (type(e).__name__, e, CFG.get("sui_url"))
        sys.stderr.write("check_sui_login: %s\n" % LOGIN_ERR["detail"])
        return None
    if user != CFG.get("sui_user") or pw != CFG.get("sui_pass"):
        # s-ui 改过密码：顺便更新中转助手连 s-ui 用的账号
        try:
            save_config({"sui_user": user, "sui_pass": pw})
            globals()["SUI"] = Sui(CFG)
        except Exception as e:
            sys.stderr.write("update sui creds: %s\n" % e)
    return True


class Handler(BaseHTTPRequestHandler):
    server_version = "relay-helper"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, body, ctype="application/json; charset=utf-8", headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        return self._session() or self._token_ok()

    def _token_ok(self):
        t = self.headers.get("X-RH-Token") or ""
        return bool(t and CFG.get("api_token") and hmac.compare_digest(t, CFG["api_token"]))

    def _remote_sid(self):
        """页面上选了别的服务器：返回服务器 id（只有用页面登录的会话才能转发，用密钥调用的不再往下转）。"""
        sid = self.headers.get("X-RH-Server") or ""
        return sid if sid and sid != "local" and self._session() else ""

    def _session(self):
        ck = self.headers.get("Cookie") or ""
        m = re.search(r"rh_sess=([A-Za-z0-9_\-]+)", ck)
        if not m:
            return False
        exp = SESSIONS.get(m.group(1))
        return bool(exp and exp > time.time())

    def _ip(self):
        return self.client_address[0]

    def setup(self):
        # HTTPS：TLS 握手放在处理线程里做，慢客户端不会卡住主线程
        if isinstance(self.request, ssl.SSLSocket):
            self.request.settimeout(15)
            self.request.do_handshake()
            self.request.settimeout(None)
        super().setup()

    def do_GET(self):
        p = CFG["path"]
        path = self.path.split("?", 1)[0]
        if path.startswith(p + "sub/"):  # 客户订阅，不需要登录，靠链接里的随机令牌
            return serve_sub(self, path[len(p + "sub/"):].strip("/"), self.path.split("?", 1)[1] if "?" in self.path else "")
        if path == p + "api/whoami":  # 只返回随机实例号，用于检查新域名是否指向本机
            return self._send(200, {"id": INSTANCE})
        if path == p + "api/backup_download":
            if not self._authed():
                return self._send(401, "请先登录", "text/plain; charset=utf-8")
            q = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
            full = (q.get("full") or ["0"])[0] == "1"
            sid = (q.get("srv") or [""])[0]
            if sid and sid != "local" and self._session():
                try:
                    sv = _server(sid)
                    with _remote(sv, "api/backup_download?full=%d" % full, timeout=600) as r:
                        self.send_response(200)
                        for hk in ("Content-Type", "Content-Length", "Content-Disposition"):
                            if r.headers.get(hk):
                                self.send_header(hk, r.headers[hk])
                        self.send_header("Cache-Control", "no-store")
                        self.end_headers()
                        shutil.copyfileobj(r, self.wfile, 256 * 1024)
                    return
                except Exception as e:
                    return self._send(502, "从服务器下载备份失败：%s" % e, "text/plain; charset=utf-8")
            try:
                fp, name = make_backup(full)
            except Exception as e:
                return self._send(500, "备份失败：%s" % e, "text/plain; charset=utf-8")
            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/gzip")
                self.send_header("Content-Length", str(os.path.getsize(fp)))
                self.send_header("Content-Disposition", "attachment; filename=\"%s\"" % name)
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                with open(fp, "rb") as f:  # 分块发送，不把整个文件读进内存
                    shutil.copyfileobj(f, self.wfile, 256 * 1024)
            finally:
                try:
                    os.remove(fp)  # 只是临时文件，下载完就删，服务器上不留
                except OSError:
                    pass
            return
        if path == p.rstrip("/"):
            return self._send(302, "", headers={"Location": p})
        if path == p or path == p + "index.html":
            with open(os.path.join(HERE, "index.html"), encoding="utf-8") as f:
                html = f.read().replace("__BASE__", p)
            return self._send(200, html, "text/html; charset=utf-8")
        return self._send(404, "not found", "text/plain")

    def _restore_upload(self):
        import tempfile
        if not self._authed():
            return self._send(401, {"ok": False, "error": "请先登录", "login": True})
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0:
            return self._send(400, {"ok": False, "error": "没有收到文件"})
        if n > RESTORE_MAX:
            return self._send(413, {"ok": False, "error": "文件太大（%.0f MB）" % (n / 1048576)})
        sid = self._remote_sid()
        if sid:  # 转发给选中的服务器去恢复
            try:
                sv = _server(sid)
                with tempfile.TemporaryFile(dir=os.path.dirname(CONFIG_PATH)) as tf:
                    left = n  # 只读上传的这 n 个字节（连接是长连接，不会自己结束）
                    while left > 0:
                        chunk = self.rfile.read(min(256 * 1024, left))
                        if not chunk:
                            break
                        tf.write(chunk)
                        left -= len(chunk)
                    tf.seek(0)
                    with _remote(sv, "api/restore_upload", data=tf, timeout=600,
                                 headers={"Content-Type": "application/octet-stream", "Content-Length": str(n)}) as r:
                        return self._send(200, r.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                return self._send(200, {"ok": False, "error": "服务器返回 HTTP %s" % e.code})
            except Exception as e:
                return self._send(200, {"ok": False, "error": "转发失败：%s" % e})
        fd, tmp = tempfile.mkstemp(prefix="rh-upload-", dir=os.path.dirname(CONFIG_PATH))
        try:
            with os.fdopen(fd, "wb") as f:  # 边收边写硬盘，不占内存
                left = n
                while left > 0:
                    chunk = self.rfile.read(min(256 * 1024, left))
                    if not chunk:
                        break
                    f.write(chunk)
                    left -= len(chunk)
            if left:
                return self._send(400, {"ok": False, "error": "上传中断，请重试"})
            try:
                res = restore_file(tmp)
                res["ok"] = True
                return self._send(200, res)
            except (SuiError, ValueError) as e:
                return self._send(200, {"ok": False, "error": str(e)})
            except Exception as e:
                traceback.print_exc()
                return self._send(200, {"ok": False, "error": "内部错误：%s" % e})
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass

    def do_POST(self):
        p = CFG["path"]
        path = self.path.split("?", 1)[0]
        if not path.startswith(p + "api/"):
            return self._send(404, {"ok": False, "error": "not found"})
        action = path[len(p + "api/"):]
        if action == "restore_upload":
            return self._restore_upload()
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n).decode("utf-8") or "{}") if n else {}
        except ValueError:
            return self._send(400, {"ok": False, "error": "bad json"})
        if action == "login":
            ip = self._ip()
            fl = [t for t in FAILS.get(ip, []) if t > time.time() - 600]
            if len(fl) >= 8:
                return self._send(429, {"ok": False, "error": "失败次数太多，10 分钟后再试"})
            # s-ui 的账号密码，或者中转助手自己的备用密码（s-ui 出问题时也能登录）
            ok = check_password(body.get("password"))
            sui_down = False
            if not ok and body.get("username"):
                r = check_sui_login(body.get("username", "").strip(), body.get("password") or "")
                ok, sui_down = bool(r), r is None
            if not ok:
                fl.append(time.time())
                FAILS[ip] = fl
                time.sleep(1)
                return self._send(200, {"ok": False, "error": "没能向 s-ui 验证账号（%s）。可以先账号留空、用中转助手的备用密码登录（cat /opt/relay-helper/config.json 里的 password）" % LOGIN_ERR["detail"]
                                        if sui_down else "账号或密码错误（和 s-ui 面板的一样）"})
            sid = secrets.token_urlsafe(32)
            SESSIONS[sid] = time.time() + SESSION_AGE
            secure = "; Secure" if CFG.get("cert_file") else ""
            return self._send(200, {"ok": True}, headers={
                "Set-Cookie": "rh_sess=%s; Path=%s; Max-Age=%d; HttpOnly; SameSite=Strict%s" % (sid, p, SESSION_AGE, secure)})
        if action == "logout":
            return self._send(200, {"ok": True}, headers={"Set-Cookie": "rh_sess=; Path=%s; Max-Age=0" % p})
        if not self._authed():
            return self._send(401, {"ok": False, "error": "请先登录", "login": True})
        sid = self._remote_sid()
        if sid and action not in LOCAL_ONLY:
            return self._send(200, proxy_json(sid, action, body))
        fn = OPS.get(action)
        if not fn:
            return self._send(404, {"ok": False, "error": "unknown action"})
        try:
            res = fn(body)
            res["ok"] = res.get("ok", True)
            return self._send(200, res)
        except (SuiError, ValueError) as e:
            return self._send(200, {"ok": False, "error": str(e)})
        except Exception as e:
            traceback.print_exc()
            return self._send(200, {"ok": False, "error": "内部错误：%s" % e})


def main():
    global CFG, SUI
    CFG = load_config()
    if not CFG["password"]:
        sys.exit("config.json 里必须设置 password")
    if not CFG["public_host"]:
        sys.exit("config.json 里必须设置 public_host（客户链接里用的域名或 IP）")
    SUI = Sui(CFG)
    try:
        SUI.login()
        print("已连接 s-ui：", CFG["sui_url"])
        reserve_ports()
    except Exception as e:
        print("警告：暂时无法登录 s-ui：", e)
    load_limits()
    load_fo()
    load_subs()
    load_servers()
    load_pool()
    threading.Thread(target=pool_loop, daemon=True).start()
    if not CFG.get("api_token"):
        save_config({"api_token": secrets.token_urlsafe(24)})
    threading.Thread(target=monitor_loop, daemon=True).start()
    threading.Thread(target=failover_loop, daemon=True).start()
    threading.Thread(target=health_loop, daemon=True).start()
    srv = ThreadingHTTPServer((CFG["listen"], int(CFG["port"])), Handler)
    scheme = "http"
    if CFG.get("cert_file") and CFG.get("key_file"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(CFG["cert_file"], CFG["key_file"])
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
        scheme = "https"

        def cert_watch():
            # 证书续签后（acme / s-ui 换了文件）自动换上新证书，不用重启
            mt = lambda: tuple(os.path.getmtime(f) for f in (CFG["cert_file"], CFG["key_file"]))
            last = mt()
            while True:
                time.sleep(3600)
                try:
                    now = mt()
                    if now != last:
                        ctx.load_cert_chain(CFG["cert_file"], CFG["key_file"])
                        last = now
                        sys.stderr.write("证书已更新\n")
                except Exception as e:
                    sys.stderr.write("cert reload: %s\n" % e)
        threading.Thread(target=cert_watch, daemon=True).start()
    print("中转助手 %s 已启动：%s://<服务器>:%s%s" % (VERSION, scheme, CFG["port"], CFG["path"]))
    srv.serve_forever()


if __name__ == "__main__":
    main()
