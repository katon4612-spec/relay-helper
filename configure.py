#!/usr/bin/env python3
"""生成 /opt/relay-helper/config.json：自动读取 s-ui 的端口/路径/管理员账号，只需填客户链接用的域名。"""
import json, os, secrets, socket, sqlite3, string, sys, subprocess, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CFG = os.path.join(HERE, "config.json")
DB_CANDIDATES = [os.environ.get("SUI_DB", ""), "/usr/local/s-ui/db/s-ui.db"]


def ask(q, default=""):
    try:
        v = input("%s%s: " % (q, " [%s]" % default if default else "")).strip()
    except EOFError:
        v = ""
    return v or default


def port_free(p):
    s = socket.socket()
    try:
        s.bind(("0.0.0.0", p))
        return True
    except OSError:
        return False
    finally:
        s.close()


def main():
    old = {}
    if os.path.exists(CFG):
        old = json.load(open(CFG, encoding="utf-8"))
        print("检测到已有配置，回车保留原值。")
    db = next((d for d in DB_CANDIDATES if d and os.path.exists(d)), None)
    st, users = {}, []
    if db:
        c = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
        st = {k: (v.decode() if isinstance(v, bytes) else v) for k, v in c.execute("select key, value from settings")}
        users = list(c.execute("select username, password from users order by id"))
        print("已读取 s-ui 配置：", db)
    else:
        print("没找到 s-ui 数据库（/usr/local/s-ui/db/s-ui.db），下面需要手动填写。")
    web_port = st.get("webPort") or "2095"
    web_path = st.get("webPath") or "/app/"
    if not web_path.startswith("/"):
        web_path = "/" + web_path
    if not web_path.endswith("/"):
        web_path += "/"
    listen = st.get("webListen") or "127.0.0.1"
    if listen in ("0.0.0.0", "::", ""):
        listen = "127.0.0.1"
    scheme = "https" if st.get("webCertFile") and st.get("webKeyFile") else "http"
    sui_url = old.get("sui_url") or "%s://%s:%s%s" % (scheme, listen, web_port, web_path)
    web_domain = st.get("webDomain") or ""

    print("\n客户链接里填的服务器地址（就是这台中转机的域名或 IP，例如 yyus.liveshop.work）")
    default_host = old.get("public_host") or web_domain or st.get("subDomain") or ""
    public_host = ""
    while not public_host:
        public_host = ask("中转机域名/IP", default_host)
    if web_domain and web_domain != public_host:
        print("⚠ 注意：s-ui 设置了面板域名 %s，与 %s 不同。工具会用面板域名访问 s-ui，但客户链接地址可能变成面板域名。" % (web_domain, public_host))

    sui_user = old.get("sui_user") or (users[0][0] if users else "")
    sui_pass = old.get("sui_pass") or (users[0][1] if users else "")
    if not sui_user or not sui_pass:
        sui_user = ask("s-ui 管理员用户名", sui_user)
        sui_pass = ask("s-ui 管理员密码", sui_pass)

    port = int(old.get("port") or 0)
    if not port:
        port = 2097
        while not port_free(port):
            port += 1
    alnum = string.ascii_letters + string.digits
    path = old.get("path") or "/" + "".join(secrets.choice(alnum) for _ in range(12)) + "/"
    password = old.get("password") or "".join(secrets.choice(alnum) for _ in range(12))

    cfg = dict(old)
    cfg.update({
        "listen": old.get("listen", "0.0.0.0"), "port": port, "path": path, "password": password,
        "sui_url": sui_url, "sui_user": sui_user, "sui_pass": sui_pass, "public_host": public_host,
        "sui_host": web_domain or "",
        "sui_restart_cmd": old.get("sui_restart_cmd", "systemctl restart s-ui"),
        "port_min": old.get("port_min", 10000), "port_max": old.get("port_max", 60000),
        "check_url": old.get("check_url", "https://www.gstatic.com/generate_204"),
        "geo_lookup": old.get("geo_lookup", True), "auto_firewall": old.get("auto_firewall", True),
        "cert_file": old.get("cert_file", st.get("webCertFile", "") or ""),
        "key_file": old.get("key_file", st.get("webKeyFile", "") or ""),
    })
    with open(CFG, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.chmod(CFG, 0o600)

    # 验证能登录 s-ui
    sys.path.insert(0, HERE)
    import app
    app.CFG = app.load_config()
    try:
        s = app.Sui(app.CFG)
        s.login()
        print("✓ 已成功登录 s-ui")
    except Exception as e:
        print("✗ 登录 s-ui 失败：%s\n  可以编辑 %s 修改 sui_url / sui_user / sui_pass 后重新运行安装脚本" % (e, CFG))


if __name__ == "__main__":
    main()
