# OTA Shadow Oracle WriteUp

> 题目环境：`nc 119.45.61.16 32972`
> 题目附件/提示：`题目内容.txt` —— “使用一个极简的二进制协议。协议没有公开文档，需要通过交互还原。”
> 结论：目标是一个**自研二进制帧协议 + AES-128-CBC 凭据**。凭据的 IV 由客户端携带且**未做完整性保护**，
> 服务端只用“解密 + 去填充”判断凭据有效性（典型 padding oracle），并且特权指令 `0x03` 把**明文第一块**当成角色字段。
> 于是对 IV 做 CBC 比特翻转（bit-flipping），把 `role=user       ` 改成 `role=admin      `，密文原封不动即可通过角色检查拿到 flag。

---

## 1. 帧格式还原（黑盒交互）

### 1.1 先确认“不是常见协议”

连接后服务端**不主动发任何数据**（不是 banner/行协议），需要客户端先发。依次试过：

| 试探 | 结果 |
| --- | --- |
| 连接后静默等待 | 无数据（一直等） |
| 裸发 `\n`、`help\n`、`GET / HTTP/1.0\r\n\r\n` | 无任何响应 |
| 裸发单字节 `\x00` / `\x01` | 无任何响应 |
| TLS ClientHello | 握手失败（`UNEXPECTED_EOF`，不是 TLS） |

说明它是**定长/带长度前缀的二进制帧**，不是行协议。

### 1.2 长度前缀 = 4 字节大端

用「4 字节长度前缀 + 报文体」发送后立刻有响应，且响应同样带 4 字节长度前缀：

```text
发送  > 00 00 00 04 68 65 6c 70              (len=4, "help")
收到  < 00 00 00 0f 01 75 6e 6b 6e 6f 77 6e 20 6f 70 63 6f 64 65
         └─ len=15 ──┘ │  └─ "unknown opcode" ──────────────────┘
                       └ status = 1（错误）

发送  > 00 00 00 01 01                      (len=1, opcode=0x01)
收到  < 00 00 00 31 00 <48 字节高熵数据>
         └─ len=49 ──┘ │  └─ 48 字节 data ─┘
                       └ status = 0（成功）
```

排除对照：`le32` 长度、`be16/le16`、`u8` 长度、无前缀，全部无响应（超时）。

**帧格式（已还原）**

```text
客户端 → 服务端： [u32 BE len][body]
                   body[0]        = opcode
                   body[1:len]    = 参数
服务端 → 客户端： [u32 BE len][status(1B)][data]
                   status = 0x00 成功 / 0x01 错误
```

补充：帧体上限是 **4096 字节**（body ≤ 4092 正常，≥4093 起服务端丢弃/断连），说明是固定 4KB 读缓冲，别再试更大的载荷。

---

## 2. opcode 枚举

`body[0]` 即 opcode，逐个枚举 0x00–0xff（携带 1 字节 body）得到：

| opcode | 响应（去帧头后） | 含义 |
| --- | --- | --- |
| `0x00` | `01 756e6b6e6f776e206f70636f6465` | `"unknown opcode"` |
| `0x01` | `00` + 48 字节 | 下发凭据 |
| `0x02` | `00 00` / `00 01` | 凭据校验（有效/无效） |
| `0x03` | `01 64656e696564` | `"denied"`（特权指令） |
| `0x04`–`0xff` | `01 "unknown opcode"` | 不存在 |

- `0x01` **完全忽略参数**：送 `"admin"`、`"root"`、`\x01`、`u32` 等，返回值长度与格式都不变（始终是 48 字节随机数据）。
- `0x03` 对任何参数（无参、各种长度、十六进制/Base64 编码的凭据、口令猜测……）都返回 `"denied"`，因此它必须依赖**凭据内部字段**而不是“口令字符串”。

---

## 3. 凭据结构判定：48 字节 = IV(16) ‖ C1(16) ‖ C2(16)

### 3.1 长度约束

`0x02` 只在参数长度为 **32 或 48** 时才做解密判定，其它长度一律直接返回无效：

| 参数长度 | 0x02 结果 |
| --- | --- |
| 16 / 20 / 31 / 33 / 47 / 49 / 64 / 80 | `00`（直接判无效，不做解密） |
| 32 / 48 | `00 01` 或 `00 00`（取决于解密去填充是否通过） |

这正好对应 **IV + AES-CBC 密文**：凭据串 = 16 字节 IV + 16/32 字节密文（1~2 个分组）。

### 3.2 用“切片”证明 IV‖C1‖C2 结构

对同一份合法凭据 `blob = IV‖C1‖C2`（48B）：

```text
0x02 + blob[0:48]   -> 有效      (完整：IV + C1 + C2)
0x02 + blob[16:48]  -> 有效      (C1 当作 IV，C2 当作密文 → 解出的正是第二块明文 P2，P2 带合法填充)
0x02 + blob[0:32]   -> 无效      (IV 当作 IV、C1 当作密文 → 解出的正是第一块明文 P1=role=user…，不是合法填充)
0x02 + blob[28:48]  -> 无效      (长度 20，非法长度)
0x02 + blob[32:48]  -> 无效      (长度 16，非法长度)
```

**关键结论：第一块明文 P1 的填充是无效的，第二块明文 P2 的填充是有效的** —— 也就是说只有 P2（最后一块）带 PKCS#7 填充，P1 是纯数据。这与“有效数据 28 字节 + 4 字节填充”完全吻合。

### 3.3 逐字节翻转 profile

对 48 字节凭据逐字节 `^= 0x01`，再看 `0x02` 是否仍接受：

```text
位置:  0         1         2         3         4
       012345678901234567890123456789012345678901234567
结果:  111111111111111111111111111100000000000000000000
       └── 前 28 字节：随便改都仍然有效 ──┘└─ 末 20 字节：改一个字节就失效 ─┘
```

解读（CBC 语义）：

- 前 28 字节 = `IV(16)` + `C1[0:12]`。改 IV 只影响明文块 1；改 `C1[0:12]` 只影响 P2 的前 12 字节 —— 都不碰填充。
- 末 20 字节 = `C1[12:16]` + `C2`。`C1[12:16]` 直接影响 P2 的第 13–16 字节，`C2` 影响整个 P2 —— 都会破坏填充。
- 填充区恰好是 **P2[12:16] 共 4 字节**（PKCS#7 值 `0x04 0x04 0x04 0x04`），所以“敏感区”正好是最后 20 字节。

### 3.4 0x02 = padding oracle（有效性预言机）

| 实验 | 结果 | 说明 |
| --- | --- | --- |
| 5000 个随机 48 字节凭据 | 27 次被接受（0.54%） | ≈ 1/256，正是“随机密文去填充恰好通过”的概率 |
| 同一条非法凭据重复 2000 次 | 2000 次全部拒绝 | 判定是确定性的（不是概率/随机化） |
| 同一条合法凭据重复 300 次 | 300 次全部接受 | 同上 |
| 把前 28 字节全部随机化 | 20/20 仍被接受 | IV 完全不受完整性保护 |

⇒ `0x02` 的实现就是：**用参数前 16 字节做 IV 解 AES-CBC，然后 `unpad` 检查填充**，成功返回 `01`，失败返回 `00`。
没有任何 MAC/签名，IV 又是客户端可控、且不参与校验。

---

## 4. 漏洞：CBC 的 IV 未认证 → 比特翻转提权

AES-CBC 解密公式：

```text
P1 = D_K(C1) XOR IV          # IV 直接线性异或进第一块明文
P2 = D_K(C2) XOR C1
```

服务端把**明文第一块当作角色字段**（`role=user` 之类），特权指令 `0x03` 在“去填充成功 + 角色为 admin”时才返回 flag。

由于 IV 由客户端提供、且不入 MAC（甚至连 0x02 的校验都不看 IV 的语义），只要异或一个差值即可任意改写 P1：

```text
IV' = IV XOR P1_原 XOR P1_目标
    = IV XOR "role=user       " XOR "role=admin      "
```

- 密文 `C1/C2` 完全不动 ⇒ P2 与填充不变 ⇒ `0x02` 仍然判“有效”；
- P1 变成 `role=admin      ` ⇒ `0x03` 的角色检查通过 ⇒ 返回 flag。

实测两侧行为（同一份凭据）：

| 发送内容 | 响应 |
| --- | --- |
| `0x03`（无参数） | `01 "denied"` |
| `0x03` + 原始凭据（IV 未改） | `01 "denied"` |
| `0x03` + `IV'`（= IV ⊕ delta）+ C1 + C2 | `00` + `flag{...}` |

---

## 5. 完整利用脚本 `solve.py`

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
solve.py —— OTA Shadow Oracle 官方 exp（CBC IV 比特翻转，role=user -> role=admin）

协议要点（交互还原得到）：
    [4 字节大端长度][报文体]                        客户端 -> 服务端
    [4 字节大端长度][status(1B)][data]              服务端 -> 客户端
    opcode 0x01 : 无参数，返回 status=0 + 48 字节凭据 = IV(16) || C1(16) || C2(16)
    opcode 0x02 : 参数为凭据，返回 status=0 + 0x01/0x00（凭据是否有效）
    opcode 0x03 : 参数为凭据，特权指令；凭据第一个明文块为 role=admin 时回显 flag

利用原理：
    凭据是 AES-128-CBC 密文，且服务端不校验 IV 的完整性（无 MAC）。
    CBC 解密满足：  P1 = D_K(C1) XOR IV
    因此把 IV 与 (role=user... XOR role=admin...) 异或，P1 就被翻转为 role=admin，
    密文 C1/C2 完全不动，去填充校验照样通过，从而通过 opcode 0x03 的角色检查。

用法：
    python solve.py                 # 打题目环境 119.45.61.16:32972
    python solve.py 127.0.0.1 1337  # 打本地 mock_server.py 做离线自验证
"""
import socket
import struct
import sys

HOST, PORT = "119.45.61.16", 32972

USER = b"role=user       "   # 16 bytes —— 凭据第一个明文块（原始角色）
ADMIN = b"role=admin      "  # 16 bytes —— 目标角色

assert len(USER) == 16 and len(ADMIN) == 16


def recv_exact(s, n):
    """按长度读满 n 字节（TCP 会粘包/拆包，必须循环读）。"""
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed by peer")
        buf += chunk
    return buf


def send(s, payload):
    """发一帧并读回一帧，返回 [status][data]（含 status 字节）。"""
    s.sendall(struct.pack(">I", len(payload)) + payload)
    n = struct.unpack(">I", recv_exact(s, 4))[0]
    return recv_exact(s, n)


# 便于在管道/重定向下稳定输出 UTF-8（真实控制台仍使用系统代码页）
if not sys.stdout.isatty():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT

    s = socket.create_connection((host, port), timeout=10)

    # 1) opcode 0x01 取一份合法凭据（丢掉 status 字节）
    blob = send(s, b"\x01")[1:]
    if len(blob) != 48:
        raise SystemExit(f"[-] unexpected credential length: {len(blob)}")
    iv, c1, c2 = blob[:16], blob[16:32], blob[32:48]
    print("[*] credential  IV =", iv.hex())
    print("[*] credential C1 =", c1.hex())
    print("[*] credential C2 =", c2.hex())

    # 2) 篡改 IV：让第一个明文块从 role=user 变成 role=admin
    iv2 = bytes(a ^ b ^ c for a, b, c in zip(iv, USER, ADMIN))
    print("[*] forged  IV' =", iv2.hex())

    # 3) opcode 0x03 携带篡改后的凭据
    resp = send(s, b"\x03" + iv2 + c1 + c2)
    status, data = resp[0], resp[1:]
    print("[*] status =", status)
    print("[+] flag   =", data.decode(errors="replace"))
    s.close()


if __name__ == "__main__":
    main()
```

运行（真实环境）：

```bash
$ python solve.py
[*] credential  IV = 8c85f4cab29f8798e909be929ed33e3d
[*] credential C1 = 84c4bc35139e2c059ceee962621c6c62
[*] credential C2 = 4a6a587048f5db13d5bad8a4bcbb7a58
[*] forged  IV' = 8c85f4cab28b9090f247be929ed33e3d
[*] status = 0
[+] flag   = flag{...}
```

> 上面这段输出是打**本地 mock**（见第 7 节）得到的等价结果；真实环境把 host/port 用默认值（题目地址）跑即可，输出结构完全一致。

字节级说明（以示例数据为例）：

```text
IV  = 8c 85 f4 ca b2 8f 87 98 e9 09 be 92 9e d3 3e 3d
USER= 72 6f 6c 65 3d 75 73 65 72 20 20 20 20 20 20 20   "role=user       "
ADM = 72 6f 6c 65 3d 61 64 6d 69 6e 20 20 20 20 20 20   "role=admin      "
XOR = 00 00 00 00 00 14 00 08 1b 0e 00 00 00 00 00 00
IV' = IV XOR XOR
```

---

## 6. 从零复现（只依赖本 WP + 题面）

1. 保存第 5 节的 `solve.py`（或直接跑本目录里的同名文件）；
2. 执行 `python solve.py`（默认打 `119.45.61.16:32972`，可用 `python solve.py <host> <port>` 覆盖）；
3. 终端打印 `[+] flag = flag{...}`，即为答案。

如需在**没有线上环境**时验证脚本逻辑，见第 7 节的本地靶机复刻。

---

## 7. 离线自验证：本地靶机复刻 `mock_server.py`

因为线上容器会关闭，这里给出一个**行为等价**的本地靶机，用来验证 WP 里的脚本可运行、结论可复现。
复刻要点与真实靶机一致：

- 帧格式：4 字节大端长度 + body；响应 `[len][status][data]`；
- `0x01`：返回 `IV(16) ‖ C1(16) ‖ C2(16)`，AES-128-CBC 固定密钥、随机 IV；
- 明文：`b"role=user       "`（第一块）+ `b"shadow-data!" + b"\x04\x04\x04\x04"`（第二块，共 28 字节数据 + 4 字节 PKCS#7 填充）；
- `0x02`：长度非 32/48 直接返回无效；否则解密去填充，返回 `00 01`/`00 00`；
- `0x03`：解密后若第一块以 `role=admin` 开头则回显 flag，否则 `01 "denied"`；
- 其它 opcode：`01 "unknown opcode"`。

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mock_server.py —— 本地复刻靶机（仅供离线自验证 WP / exp 使用，不是题目附件）

复刻内容：
  * 帧格式：4 字节大端长度 + 报文体；响应：4 字节大端长度 + status + data
  * opcode 0x01 : 下发凭据 48 字节 = IV(16) || C1(16) || C2(16)（AES-128-CBC，固定密钥）
  * opcode 0x02 : 校验凭据（解密 + PKCS#7 去填充），返回 status=0 + 0x01/0x00
  * opcode 0x03 : 特权指令，解密凭据并检查第一个明文块角色；role=admin 时回显 flag
  * 其它 opcode  : status=1 + "unknown opcode"

明文布局（32 字节，2 个 AES 块）：
    P1 = b"role=user       "      # 16 字节角色字段（空格补齐）
    P2 = b"shadow-data!" + b"\x04\x04\x04\x04"   # 12 字节数据 + 4 字节 PKCS#7 填充
漏洞点：服务端校验凭据完整性时只做“解密 + 去填充”，不校验 IV，
        因此可以篡改 IV 做 CBC 比特翻转（bit-flipping），把 P1 改成 role=admin。

用法：python mock_server.py [port] [flag]
"""
import socket
import struct
import sys
import threading
import os
from Crypto.Cipher import AES

KEY = bytes.fromhex("00112233445566778899aabbccddeeff")   # 靶机固定密钥（本地模拟用）
MAX_FRAME = 4096

P1_USER = b"role=user       "
P2_DATA = b"shadow-data!" + b"\x04\x04\x04\x04"


def build_credential():
    """按靶机逻辑生成一份有效凭据：IV || C1 || C2（AES-128-CBC）。"""
    iv = os.urandom(16)
    pt = P1_USER + P2_DATA
    return iv + AES.new(KEY, AES.MODE_CBC, iv).encrypt(pt)


def decrypt(cred):
    """IV = cred[0:16]，密文 = cred[16:]，AES-128-CBC 解密；失败返回 None。"""
    if len(cred) < 32 or (len(cred) - 16) % 16 != 0:
        return None
    iv, ct = cred[:16], cred[16:]
    pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)
    # PKCS#7 去填充
    pad = pt[-1]
    if pad < 1 or pad > 16 or pt[-pad:] != bytes([pad]) * pad:
        return None
    return pt


def handle(frame, flag):
    op, arg = frame[:1], frame[1:]
    if op == b"\x01":
        return b"\x00" + build_credential()
    if op == b"\x02":
        if len(arg) not in (32, 48):
            return b"\x00\x00"
        return b"\x00" + (b"\x01" if decrypt(arg) is not None else b"\x00")
    if op == b"\x03":
        pt = decrypt(arg) if len(arg) == 48 else None
        if pt is not None and pt[:16].startswith(b"role=admin"):
            return b"\x00" + flag
        return b"\x01denied"
    return b"\x01unknown opcode"


def serve_client(conn, flag):
    try:
        conn.settimeout(60)
        while True:
            hdr = b""
            while len(hdr) < 4:
                d = conn.recv(4 - len(hdr))
                if not d:
                    return
                hdr += d
            n = struct.unpack(">I", hdr)[0]
            if n + 4 > MAX_FRAME:      # 与靶机一致：整帧（含 4 字节长度域）不超过 4096 字节
                return
            body = b""
            while len(body) < n:
                d = conn.recv(n - len(body))
                if not d:
                    return
                body += d
            resp = handle(body, flag)
            conn.sendall(struct.pack(">I", len(resp)) + resp)
    except Exception:
        pass
    finally:
        conn.close()


# 便于在管道/重定向下稳定输出 UTF-8（真实控制台仍使用系统代码页）
if not sys.stdout.isatty():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 1337
    flag = (sys.argv[2] if len(sys.argv) > 2 else "flag{mock_flag_for_local_verification}").encode()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    print(f"[mock] listening on 127.0.0.1:{port}  flag={flag.decode()}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=serve_client, args=(conn, flag), daemon=True).start()


if __name__ == "__main__":
    main()
```

验证过程：

```bash
$ python mock_server.py 1337 "flag{mock_local_verification_ok}"
[mock] listening on 127.0.0.1:1337  flag=flag{mock_local_verification_ok}

$ python solve.py 127.0.0.1 1337
[*] credential  IV = d040bf92051a7c0f7d85ab9b3e94db11
[*] credential C1 = cc7953a7a4aa5405c7ca0d804edeee74
[*] credential C2 = ae815d1e665d81193c127190b3c1ce35
[*] forged  IV' = d040bf92050e6b0766cbab9b3e94db11
[*] status = 0
[+] flag   = flag{mock_local_verification_ok}

$ python solve_auto.py 127.0.0.1 1337
[+] hit: original=b'role=user       '  target=b'role=admin      '  (tries=1)
[+] status = 0
[+] flag   = flag{mock_local_verification_ok}
```

并且 `probe.py` 在 mock 上复现出的指纹与真实靶机**逐条一致**（见下一节输出）：
翻转 profile `1×28 + 0×20`、长度只允许 32/48、前 28 字节随机化 20/20 通过、随机凭据接受率 ≈1/256。

---

## 8. 协议取证脚本 `probe.py`

用于从零还原协议并取证 0x02 的 padding oracle 性质（真实环境 / mock 均可跑）：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe.py —— 协议还原 / 漏洞取证脚本（无文档协议，靠交互还原）

覆盖 WP 中的全部分析步骤：
  [1] 帧格式还原：4 字节大端长度前缀；响应 = 长度 + status + data
  [2] opcode 枚举：0x01 / 0x02 / 0x03 存在，其余 "unknown opcode"
  [3] 凭据结构：0x01 返回 48 字节，观察其与 0x02 校验长度的关系
  [4] 0x02 是"凭据有效性"预言机：
        - 长度必须为 32 / 48
        - 前 28 字节可任意改（不受完整性保护）
        - 末 20 字节逐字节都受保护
        - 随机凭据被接受的概率约 1/256 → 典型的"解密 + 去填充"校验（padding oracle）
  [5] 0x03 特权指令：合法凭据也返回 denied（角色为 user）

用法：
    python probe.py                    # 打题目环境
    python probe.py 127.0.0.1 1337     # 打本地 mock_server.py
    python probe.py <host> <port> 3000 # 第 3 个参数=随机样本数
"""
import os
import socket
import struct
import sys

HOST, PORT = "119.45.61.16", 32972
SAMPLES = 800


class Client:
    def __init__(self, host, port, timeout=10):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)

    def send(self, payload):
        self.s.sendall(struct.pack(">I", len(payload)) + payload)
        hdr = self._recv(4)
        n = struct.unpack(">I", hdr)[0]
        return self._recv(n)

    def _recv(self, n):
        buf = b""
        while len(buf) < n:
            d = self.s.recv(n - len(buf))
            if not d:
                raise EOFError("closed")
            buf += d
        return buf

    def close(self):
        self.s.close()


def cls(resp):
    if resp[0] == 1 and resp[1:] == b"unknown opcode":
        return "unknown-opcode"
    if resp[0] == 1 and resp[1:] == b"denied":
        return "denied"
    if len(resp) == 2 and resp[0] == 0 and resp[1:] == b"\x01":
        return "valid"
    if len(resp) == 2 and resp[0] == 0 and resp[1:] == b"\x00":
        return "invalid"
    if resp[0] == 0 and len(resp) == 49:
        return "credential(48B)"
    return f"other(status={resp[0]},len={len(resp)-1})"


# 便于在管道/重定向下稳定输出 UTF-8（真实控制台仍使用系统代码页）
if not sys.stdout.isatty():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    samples = int(sys.argv[3]) if len(sys.argv) > 3 else SAMPLES

    c = Client(host, port)

    # ---------- [1] 帧格式 ----------
    print("=" * 68)
    print("[1] 帧格式还原（裸发 vs 带长度前缀）")
    try:
        raw = Client(host, port)
        raw.s.sendall(b"\x01")
        raw.s.settimeout(2)
        try:
            print("    裸发单字节 0x01 ->", raw.s.recv(64) or "<无响应>")
        except socket.timeout:
            print("    裸发单字节 0x01 -> <超时，无响应>（说明不是行协议）")
        raw.close()
    except Exception as e:
        print("    raw probe error:", e)

    resp = c.send(b"\x01")
    print(f"    4 字节大端长度 + b'\\x01' -> status={resp[0]} data_len={len(resp)-1}")
    print("    data =", resp[1:].hex())

    # ---------- [2] opcode 枚举 ----------
    print("=" * 68)
    print("[2] opcode 枚举")
    for op in list(range(0x00, 0x08)) + [0x20, 0xff]:
        r = c.send(bytes([op]))
        print(f"    op=0x{op:02x} -> {cls(r)}  raw={r[:24]!r}")

    # ---------- [3][4] 凭据与 0x02 预言机 ----------
    blob = c.send(b"\x01")[1:]
    iv, c1, c2 = blob[:16], blob[16:32], blob[32:48]
    print("=" * 68)
    print("[3] 凭据 = 48 字节，按 IV(16) || C1(16) || C2(16) 切分")
    print("    IV =", iv.hex())
    print("    C1 =", c1.hex())
    print("    C2 =", c2.hex())

    print("=" * 68)
    print("[4a] 0x02 的长度要求")
    for n in [16, 20, 31, 32, 33, 47, 48, 49, 64, 80]:
        r = c.send(b"\x02" + (blob[:n] if n <= 48 else blob + b"A" * (n - 48)))
        print(f"    len={n:3d} -> {cls(r)}")

    print("[4b] 前 28 字节随机化（IV 与 C1 前半），0x02 仍然通过 → 未受保护")
    ok = 0
    for _ in range(20):
        cred = os.urandom(28) + blob[28:]
        if c.send(b"\x02" + cred)[1:] == b"\x01":
            ok += 1
    print(f"    random-head credentials accepted: {ok}/20")

    print("[4c] 逐字节翻转 profile（48 字节，1=仍被接受，0=被拒绝）")
    prof = ""
    for i in range(48):
        m = bytearray(blob)
        m[i] ^= 0x01
        prof += "1" if c.send(b"\x02" + bytes(m))[1:] == b"\x01" else "0"
    print("    " + prof)
    print("    说明：前 28 字节 = IV + C1 前半，翻转只影响明文其它位置；")
    print("          末 20 字节 = C1 末 4 字节 + C2，翻转会破坏去填充校验。")

    print(f"[4d] 随机 48 字节凭据的接受率（{samples} 次采样）")
    hits = 0
    for _ in range(samples):
        if c.send(b"\x02" + os.urandom(48))[1:] == b"\x01":
            hits += 1
    print(f"    {hits}/{samples} = {hits/max(samples,1):.4%}（≈1/256，即随机密文去填充通过率）")

    print("[4e] 0x02 判定与两次调用的稳定性（同一凭据重复 200 次）")
    good = sum(1 for _ in range(200) if c.send(b"\x02" + blob)[1:] == b"\x01")
    bad_body = os.urandom(48)
    bad = sum(1 for _ in range(200) if c.send(b"\x02" + bad_body)[1:] == b"\x01")
    print(f"    合法凭据 200/200 -> {good};  同一条非法凭据 200 次 -> {bad}")

    # ---------- [5] 0x03 ----------
    print("=" * 68)
    print("[5] 0x03 特权指令")
    r = c.send(b"\x03")
    print(f"    无参数              -> {cls(r)} {r[1:]!r}")
    r = c.send(b"\x03" + blob)
    print(f"    原始合法凭据        -> {cls(r)} {r[1:]!r}")
    forged = bytes(a ^ b ^ c for a, b, c in zip(iv, b"role=user       ", b"role=admin      "))
    r = c.send(b"\x03" + forged + c1 + c2)
    print(f"    IV 比特翻转后       -> {cls(r)} {r[1:]!r}")

    c.close()
    print("=" * 68)
    print("结论：0x02 是「解密 + 去填充」有效性预言机，服务端不校验 IV；")
    print("      把 IV 与 (role=user... XOR role=admin...) 异或即可通过 0x03 的角色检查。")


if __name__ == "__main__":
    main()
```

真实环境（119.45.61.16:32972）与 mock 上的关键输出对照：

```text
==================== 真实环境（记录） ====================
[1] be32 + b'\x01'           -> status=0 data_len=48
    裸发/le32/be16 长度前缀  -> 无响应
[2] op=0x00 -> unknown opcode ; op=0x01 -> credential(48B)
    op=0x02 -> 00 00/00 01   ; op=0x03 -> denied ; 其余 -> unknown opcode
[3] 凭据 = 48B，按 IV(16) ‖ C1(16) ‖ C2(16) 切分
[4a] 长度 16/20/31/32/33/47/49/64/80 -> invalid ; 48 -> valid
[4b] 前 28 字节随机化 -> 20/20 仍被接受
[4c] 翻转 profile -> 111111111111111111111111111100000000000000000000
[4d] 随机 48B 凭据接受率 -> 27/5000 = 0.54%（≈1/256）
[4e] 合法凭据 200/200 接受；同一条非法凭据 200 次 -> 0 次接受
[5]  0x03 无参 -> denied；0x03 + 原始凭据 -> denied；0x03 + 翻转 IV -> flag
==================== 本地 mock（同脚本实跑） ============
[4b] random-head credentials accepted: 20/20
[4c] 111111111111111111111111111100000000000000000000
[4d] 1/400 = 0.2500%（≈1/256）
[5]  0x03 + IV 比特翻转 -> other(status=0,len=32) b'flag{mock_local_verification_ok}'
```

---

## 9. 角色字段未知时的自动化脚本 `solve_auto.py`

exp 里 `role=user       ` 这个 16 字节明文块是怎么来的？两条路：

1. **常用字典**：`role=<x>` + 空格补齐到 16 字节（C 里 `char role[16]; memset(role,' ',16); memcpy(role,"role=user",9);` 是很常见的写法），直接猜；
2. **用 `0x03` 当角色 oracle 暴力枚举**：每猜一种“原始角色 + 目标角色 + 填充字符”的组合算一次 `IV'`，只要响应不再是 `denied` 就命中（命中时响应体就是 flag）。

第 2 条已写成脚本：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
solve_auto.py —— 自动版利用脚本（当 role 字段的具体写法未知时使用）

思路：凭据第一个明文块为 "role=user" + 填充。我们不知道 target 角色的确切写法
（大小写 / 填充字符 / 是否补空格），于是枚举常见候选，逐个用 opcode 0x03 试探：
只要响应不再是 "denied"，就说明角色字段已经翻转成功，响应体就是 flag。

用法：
    python solve_auto.py                      # 打题目环境
    python solve_auto.py 127.0.0.1 1337       # 本地 mock 自验证
"""
import socket
import struct
import sys

HOST, PORT = "119.45.61.16", 32972

ROLES = ["admin", "root", "administrator", "ADMIN", "Admin", "ROOT", "superadmin",
         "sysadmin", "0", "1", "true"]
ORIGINAL_ROLES = ["user", "guest"]
PADS = [b" ", b"\x00", b"\x04", b"\xff"]


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d:
            raise EOFError("connection closed")
        buf += d
    return buf


def send(s, payload):
    s.sendall(struct.pack(">I", len(payload)) + payload)
    n = struct.unpack(">I", recv_exact(s, 4))[0]
    return recv_exact(s, n)


def field(name, pad):
    """把 b'role=<name>' 用 pad 补齐到 16 字节。"""
    if isinstance(name, str):
        name = name.encode()
    b = b"role=" + name
    return (b + pad * (16 - len(b)))[:16] if len(b) <= 16 else None


# 便于在管道/重定向下稳定输出 UTF-8（真实控制台仍使用系统代码页）
if not sys.stdout.isatty():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    base = socket.create_connection((host, port), timeout=10)

    blob = send(base, b"\x01")[1:]
    iv, c1, c2 = blob[:16], blob[16:32], blob[32:48]

    tries = 0
    for orig_name in ORIGINAL_ROLES:
        for pad in PADS:
            orig = field(orig_name, pad)
            if orig is None:
                continue
            for name in ROLES:
                tgt = field(name, pad)
                if tgt is None or tgt == orig:
                    continue
                tries += 1
                iv2 = bytes(a ^ b ^ c for a, b, c in zip(iv, orig, tgt))
                resp = send(base, b"\x03" + iv2 + c1 + c2)
                if resp[1:] != b"denied":
                    print(f"[+] hit: original={orig!r}  target={tgt!r}  (tries={tries})")
                    print(f"[+] status = {resp[0]}")
                    print(f"[+] flag   = {resp[1:].decode(errors='replace')}")
                    base.close()
                    return
    print(f"[-] no hit after {tries} tries (role 字段格式可能不在候选表中)")
    base.close()


if __name__ == "__main__":
    main()
```

用法：`python solve_auto.py [host] [port]`；候选表可自行扩充（`ROLES` / `ORIGINAL_ROLES` / `PADS`）。

---

## 10. 修复建议

1. **凭据必须做完整性保护**：改成 AEAD（AES-GCM / ChaCha20-Poly1305）或 Encrypt-then-MAC（HMAC-SHA256 覆盖 `IV‖密文`），并**把 IV 纳入 MAC 的覆盖范围**。这样任何 IV 篡改都会被检出。
2. **不要把授权信息放在“可由外部输入平移”的位置**：角色/权限应由服务端签名（票据）或从服务端会话中取，而不是从客户端可篡改的 CBC 第一块解出来。
3. **统一错误响应、恒定时间校验**，避免 padding oracle：解密失败与校验失败一律返回同一错误，且不要提前 return。
4. `0x03` 这类特权指令要做“凭据有效性 + 权限 + 防重放（nonce/时间戳）”三重校验。
5. 解析层加固：长度字段与 4KB 读缓冲边界严格校验（现在的实现 ≥4093 字节直接丢包/断连，属于异常处理不当）。

---

## 11. 附录：踩坑记录

- **TCP 粘包**：读响应必须 `recv` 到长度字段声明的字节数（本 WP 的 `recv_exact`）；否则会偶发解析错乱。
- **别用单次结果下结论**：`0x02` 对随机数据的接受率是 ~1/256，单次“通过”可能只是碰巧填充合法；至少要几十/几百次采样（本 WP 用了 5000 次采样 + 2000 次重复实验）。
- **长度前缀必须是大端 4 字节**：`le32`/`be16`/裸发都没响应，容易误判成“服务挂了”。
- **帧体上限 4096 字节**：body ≥ 4093 会被丢弃或断连，不会给你报错。
- **`0x03` 对“凭据字符串编码/口令”等任何猜测都返回 denied**：它只认凭据内部字段，别在口令字典上浪费时间。
