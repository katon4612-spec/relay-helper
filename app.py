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
VERSION = "1.0.0"

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
    route_of = {}
    for r in rules:
        if r.get("action", "route") == "route" and r.get("outbound"):
            for t in r.get("inbound") or []:
                route_of.setdefault(t, r["outbound"])
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
        tag = inb.get("tag")
        ot = route_of.get(tag)
        ob = outbounds.get(ot) if ot else None
        cl = clients_by_inb.get(inb.get("id"), [])
        main = next((c for c in cl if c.get("name") == tag), cl[0] if cl else None)
        rows.append({
            "tag": tag,
            "inbound_id": inb.get("id"),
            "type": inb.get("type"),
            "port": inb.get("listen_port"),
            "outbound_tag": ot,
            "outbound_id": ob.get("id") if ob else None,
            "landing_type": ob.get("type") if ob else None,
            "landing": ("%s:%s" % (ob.get("server"), ob.get("server_port"))) if ob and ob.get("server") else (ot or ""),
            "landing_user": (ob or {}).get("username", ""),
            "client_id": main.get("id") if main else None,
            "client_name": main.get("name") if main else None,
            "clients": len(cl),
            "enable": bool(main.get("enable")) if main else None,
            "expiry": main.get("expiry") if main else None,
            "up": main.get("up") if main else 0,
            "down": main.get("down") if main else 0,
        })
    rows.sort(key=lambda r: r.get("inbound_id") or 0, reverse=True)
    return rows


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
      - hysteria2 的 UDP 端口经常不被释放，内核启动失败（address already in use），所有节点掉线；
      - 异步重启和后续请求会竞争，内核状态错乱，之后的操作可能卡死。
    所以这里直接重启整个 s-ui 服务（干净启动，约 2~4 秒），再等内核恢复。
    返回: "restarted" | "ok"(未配置重启命令但内核在跑) | "down"
    """
    cmd = CFG.get("sui_restart_cmd") or ""
    if not cmd:
        return "ok" if wait_core(8) else "down"
    time.sleep(0.5)
    try:
        subprocess.run(cmd, shell=True, timeout=60, capture_output=True)
    except Exception:
        return "ok" if wait_core(8) else "down"
    deadline = time.time() + 40
    time.sleep(2)
    while time.time() < deadline:
        if core_running():
            return "restarted"
        time.sleep(1)
    return "down"


# ----------------------------------------------------------- operations --
def op_preview(body):
    lines = [l for l in (body.get("text") or "").splitlines() if l.strip()]
    customer = (body.get("customer") or "").strip()
    data = SUI.load_all()
    taken = {i.get("tag") for i in data.get("inbounds") or []} | {o.get("tag") for o in data.get("outbounds") or []} | {c.get("name") for c in data.get("clients") or []}
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
    for it in items:
        if it.get("error"):
            continue
        it["country"] = geo.get(it["ip"], "")
        base = it["name_override"] or ("%s%s%s" % (it["country"], customer, it["host"]))
        it["name"] = unique_name(base, taken)
    return {"items": items}


def op_create(body):
    items = [it for it in body.get("items") or [] if not it.get("error") and it.get("name")]
    proto = body.get("protocol") or "vless"
    expiry = int(body.get("expiry") or 0)
    if not items:
        raise SuiError("没有可创建的线路")
    with LOCK:
        data = SUI.load_all()
        taken_names = {i.get("tag") for i in data.get("inbounds") or []} | {o.get("tag") for o in data.get("outbounds") or []} | {c.get("name") for c in data.get("clients") or []}
        taken_ports = used_ports(data)
        settings = SUI.get("settings") or {}
        for k in ("webPort", "subPort"):
            try:
                taken_ports.add(int(settings.get(k)))
            except (TypeError, ValueError):
                pass
        tls_id = 0
        if proto == "vless":
            tls_id = find_tls(data, "reality")
            if not tls_id:
                raise SuiError("s-ui 里没有 Reality 配置。请先在面板「TLS 设置」里添加一个 reality 类型的配置")
        elif proto == "hysteria2":
            tls_id = find_tls(data, "cert")
            if not tls_id:
                raise SuiError("s-ui 里没有证书类 TLS 配置（hysteria2 需要）。请先在面板「TLS 设置」里添加")
        elif proto != "socks":
            raise SuiError("不支持的入站协议：" + proto)

        results = []
        new_rules = []
        for it in items:
            name = it["name"]
            if name in taken_names:
                name = unique_name(name, taken_names)
            else:
                taken_names.add(name)
            created = {}
            try:
                ob = dict(it["outbound"])
                ob["tag"] = name
                SUI.save("outbounds", "new", ob)
                created["outbound"] = name
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
                          "links": [], "volume": 0, "expiry": expiry, "up": 0, "down": 0,
                          "desc": "中转助手创建", "group": body.get("customer") or ""}
                res = SUI.save("clients", "new", client)
                cid = next((c["id"] for c in (res or {}).get("clients") or [] if c.get("name") == name), None)
                created["client"] = cid
                new_rules.append({"inbound": [name], "auth_user": [name], "action": "route", "outbound": name})
                fw = open_firewall(port, proto == "hysteria2")
                results.append({"name": name, "port": port, "client_id": cid, "ok": True, "firewall": fw})
            except Exception as e:
                # roll back the pieces of this one relay
                try:
                    if created.get("client"):
                        SUI.save("clients", "del", created["client"])
                    if created.get("inbound"):
                        SUI.save("inbounds", "del", name)
                    if created.get("outbound"):
                        SUI.save("outbounds", "del", name)
                except Exception:
                    pass
                results.append({"name": name, "ok": False, "error": str(e)})
        if new_rules:
            cfg = SUI.get("config")
            cfg = cfg.get("config", cfg) if isinstance(cfg, dict) and "config" in cfg and isinstance(cfg.get("config"), dict) else cfg
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
                        for obj, key in (("clients", r.get("client_id")), ("inbounds", r["name"]), ("outbounds", r["name"])):
                            try:
                                if key:
                                    SUI.save(obj, "del", key)
                            except Exception:
                                pass
                        r.update(ok=False, error="保存路由失败，已回滚：%s" % e)
                return {"results": results, "core": "ok"}
            core = ensure_core()
        else:
            core = "ok"
    # links
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
    return {"relays": build_relays(data), "now": int(time.time()), "public_host": CFG["public_host"]}


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
        ob, host, remark = parse_landing(raw)
        ob["tag"] = row["outbound_tag"]
        ob["id"] = row["outbound_id"]
        SUI.save("outbounds", "edit", ob)
    chk = op_check({"tags": [row["outbound_tag"]]})["results"][0]
    return {"ok": True, "landing": "%s:%s" % (ob.get("server"), ob.get("server_port")), "check": chk}


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
                SUI.save("clients", "edit", c)
                out.append({"client_id": cid, "ok": True})
            except Exception as e:
                out.append({"client_id": cid, "ok": False, "error": str(e)})
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
        deleted = set()
        for t in tags:
            row = rows.get(t)
            if not row:
                out.append({"tag": t, "ok": False, "error": "不存在"})
                continue
            try:
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
                out.append({"tag": t, "ok": True})
            except Exception as e:
                out.append({"tag": t, "ok": False, "error": str(e)})
        core = "ok"
        if deleted:
            cfg = SUI.get("config")
            cfg = cfg.get("config", cfg) if isinstance(cfg, dict) and isinstance(cfg.get("config"), dict) else cfg
            rules = (cfg.get("route") or {}).get("rules") or []
            newrules = []
            for r in rules:
                inb = r.get("inbound")
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
            for t in deleted:
                ot = rows[t].get("outbound_tag")
                if ot and ot not in still_used and ot != "direct":
                    try:
                        SUI.save("outbounds", "del", ot)
                    except Exception:
                        pass
    return {"results": out, "core": core}


def op_status(body):
    data = SUI.load_all()
    return {
        "ok": True, "version": VERSION, "public_host": CFG["public_host"],
        "reality_tls": find_tls(data, "reality"), "cert_tls": find_tls(data, "cert"),
        "inbounds": len(data.get("inbounds") or []), "clients": len(data.get("clients") or []),
    }


OPS = {
    "status": op_status, "list": op_list, "preview": op_preview, "create": op_create,
    "check": op_check, "check_raw": op_check_raw, "replace": op_replace,
    "update_clients": op_update_clients, "delete": op_delete, "links": op_links, "qr": op_qr,
}

# ------------------------------------------------------------- web server --
SESSIONS = {}
FAILS = {}
SESSION_AGE = 7 * 86400


def check_password(p):
    return hmac.compare_digest(hashlib.sha256((p or "").encode()).digest(),
                               hashlib.sha256(CFG["password"].encode()).digest()) and bool(CFG["password"])


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
        ck = self.headers.get("Cookie") or ""
        m = re.search(r"rh_sess=([A-Za-z0-9_\-]+)", ck)
        if not m:
            return False
        exp = SESSIONS.get(m.group(1))
        return bool(exp and exp > time.time())

    def _ip(self):
        return self.client_address[0]

    def do_GET(self):
        p = CFG["path"]
        path = self.path.split("?", 1)[0]
        if path == p.rstrip("/"):
            return self._send(302, "", headers={"Location": p})
        if path == p or path == p + "index.html":
            with open(os.path.join(HERE, "index.html"), encoding="utf-8") as f:
                html = f.read().replace("__BASE__", p)
            return self._send(200, html, "text/html; charset=utf-8")
        return self._send(404, "not found", "text/plain")

    def do_POST(self):
        p = CFG["path"]
        path = self.path.split("?", 1)[0]
        if not path.startswith(p + "api/"):
            return self._send(404, {"ok": False, "error": "not found"})
        action = path[len(p + "api/"):]
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
            if not check_password(body.get("password")):
                fl.append(time.time())
                FAILS[ip] = fl
                time.sleep(1)
                return self._send(200, {"ok": False, "error": "密码错误"})
            sid = secrets.token_urlsafe(32)
            SESSIONS[sid] = time.time() + SESSION_AGE
            secure = "; Secure" if CFG.get("cert_file") else ""
            return self._send(200, {"ok": True}, headers={
                "Set-Cookie": "rh_sess=%s; Path=%s; Max-Age=%d; HttpOnly; SameSite=Strict%s" % (sid, p, SESSION_AGE, secure)})
        if action == "logout":
            return self._send(200, {"ok": True}, headers={"Set-Cookie": "rh_sess=; Path=%s; Max-Age=0" % p})
        if not self._authed():
            return self._send(401, {"ok": False, "error": "请先登录", "login": True})
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
    except Exception as e:
        print("警告：暂时无法登录 s-ui：", e)
    srv = ThreadingHTTPServer((CFG["listen"], int(CFG["port"])), Handler)
    scheme = "http"
    if CFG.get("cert_file") and CFG.get("key_file"):
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CFG["cert_file"], CFG["key_file"])
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        scheme = "https"
    print("中转助手 %s 已启动：%s://<服务器>:%s%s" % (VERSION, scheme, CFG["port"], CFG["path"]))
    srv.serve_forever()


if __name__ == "__main__":
    main()
