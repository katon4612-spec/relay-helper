#!/usr/bin/env python3
"""从旧的「限时代理网关」(socks-gateway: Docker + PostgreSQL + sing-box) 导出客户，给中转助手导入。

在旧服务器上用 root 运行：
    python3 gateway_export.py                # 默认目录 /opt/socks-gateway
    python3 gateway_export.py /path/to/dir   # 部署目录不一样时

会生成 /root/gateway-export.json（里面有客户密码、落地账号，导入完请删除）。
只导出「正在使用」的客户（没停用、没到期的），它们的端口、账号密码 / UUID、Reality 密钥都原样带走，
导入中转助手后客户手里的链接不用换。
"""
import json
import os
import subprocess
import sys
import time

DIR = sys.argv[1] if len(sys.argv) > 1 else "/opt/socks-gateway"
OUT = "/root/gateway-export.json"


def die(msg):
    print("\n✗ " + msg)
    sys.exit(1)


def compose_cmd():
    for c in (["docker", "compose"], ["docker-compose"]):
        try:
            if subprocess.run(c + ["version"], capture_output=True, timeout=20).returncode == 0:
                return c
        except Exception:
            pass
    die("没找到 docker compose，确认这台是旧网关服务器")


def run(args, **kw):
    r = subprocess.run(args, cwd=DIR, capture_output=True, text=True, timeout=120, **kw)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip()[:500])
    return r.stdout


def read_env():
    env = {}
    for fn in (".env",):
        p = os.path.join(DIR, fn)
        if os.path.exists(p):
            for line in open(p, encoding="utf-8", errors="replace"):
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def read_singbox(dc):
    try:
        return json.loads(run(dc + ["exec", "-T", "gateway", "cat", "/var/lib/gateway/sing-box.json"]))
    except Exception as e:
        first = e
    # 网关容器没在运行：直接去 Docker 卷里找
    try:
        vols = run(["docker", "volume", "ls", "-q"]).split()
        for v in vols:
            if v.endswith("singbox_config"):
                mp = json.loads(run(["docker", "volume", "inspect", v]))[0]["Mountpoint"]
                with open(os.path.join(mp, "sing-box.json")) as f:
                    return json.load(f)
    except Exception:
        pass
    die("读不到网关的 sing-box 配置：%s\n请确认旧网关还在运行（docker compose ps），先别停它，导出后再停。" % first)


def read_customers(dc):
    sql = ("SELECT c.id,c.username,c.protocol,c.public_port,EXTRACT(EPOCH FROM c.expires_at)::bigint,"
           "c.enabled,u.id,u.name,u.host,u.port FROM customers c JOIN upstreams u ON u.id=c.upstream_id ORDER BY c.id")
    try:
        out = run(dc + ["exec", "-T", "db", "psql", "-U", "gateway", "-d", "gateway", "-At", "-F", "\t", "-c", sql])
    except Exception as e:
        die("读不到数据库：%s" % e)
    rows = []
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) < 10:
            continue
        rows.append({"id": int(p[0]), "username": p[1], "protocol": p[2], "port": int(p[3]), "expires": int(p[4]),
                     "enabled": p[5] in ("t", "true"), "upstream_id": int(p[6]), "upstream_name": p[7],
                     "upstream_host": p[8], "upstream_port": int(p[9])})
    return rows


def main():
    if os.geteuid() != 0:
        die("请用 root 运行")
    if not os.path.isdir(DIR):
        die("目录 %s 不存在。旧网关装在别的目录的话：python3 gateway_export.py 那个目录" % DIR)
    dc = compose_cmd()
    env = read_env()
    sb = read_singbox(dc)
    rows = read_customers(dc)
    inb = {i.get("tag"): i for i in sb.get("inbounds") or []}
    obs = {o.get("tag"): o for o in sb.get("outbounds") or []}
    route = {}
    for r in (sb.get("route") or {}).get("rules") or []:
        for t in r.get("inbound") or []:
            route[t] = r.get("outbound")
    reality = {}
    for i in inb.values():
        rl = ((i.get("tls") or {}).get("reality") or {})
        if rl.get("private_key"):
            reality = {"private_key": rl["private_key"], "short_id": (rl.get("short_id") or [""])[0],
                       "server_name": (i.get("tls") or {}).get("server_name") or (rl.get("handshake") or {}).get("server") or "www.apple.com",
                       "handshake": (rl.get("handshake") or {}).get("server") or "www.apple.com"}
            break
    now = time.time()
    customers, skipped = [], []
    for c in rows:
        tag = "customer-%d" % c["id"]
        i = inb.get(tag)
        if not i:
            why = "已停用" if not c["enabled"] else ("已到期" if c["expires"] <= now else "不在运行配置里")
            skipped.append({"username": c["username"], "protocol": c["protocol"], "port": c["port"], "reason": why})
            continue
        u = (i.get("users") or [{}])[0]
        secret = u.get("password") if c["protocol"] in ("socks", "hysteria2") else u.get("uuid")
        ob = obs.get(route.get(tag)) or {}
        if not secret or not ob:
            skipped.append({"username": c["username"], "protocol": c["protocol"], "port": c["port"], "reason": "配置不完整"})
            continue
        customers.append({
            "id": c["id"], "username": c["username"], "protocol": c["protocol"], "port": int(i.get("listen_port") or c["port"]),
            "socks_user": u.get("username") or c["username"], "secret": secret, "expires": c["expires"],
            "upstream": {"name": c["upstream_name"], "host": ob.get("server") or c["upstream_host"],
                         "port": int(ob.get("server_port") or c["upstream_port"]),
                         "username": ob.get("username") or "", "password": ob.get("password") or ""}})
    bundle = {"type": "socks-gateway-export", "version": 1, "exported": int(now),
              "public_host": env.get("PUBLIC_PROXY_HOST", ""), "admin_domain": env.get("ADMIN_DOMAIN", ""),
              "reality": reality, "customers": customers, "skipped": skipped}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(bundle, f, ensure_ascii=False, indent=1)
    os.chmod(OUT, 0o600)
    by = {}
    for c in customers:
        by[c["protocol"]] = by.get(c["protocol"], 0) + 1
    print("\n✓ 已导出到 %s" % OUT)
    print("  正在使用的客户：%d 个（%s）" % (len(customers), "，".join("%s %d" % (k, v) for k, v in sorted(by.items())) or "无"))
    print("  不导出（已停用 / 已到期）：%d 个" % len(skipped))
    print("  落地：%d 个" % len({(c["upstream"]["host"], c["upstream"]["port"], c["upstream"]["username"]) for c in customers}))
    print("  客户链接里的域名：%s" % (bundle["public_host"] or "（没读到，导入时会用中转助手的域名）"))
    print("\n这个文件里有客户密码和落地账号，导入完成后请删除：rm %s" % OUT)


if __name__ == "__main__":
    main()
