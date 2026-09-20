# UDS Zero — WriteUp

> **分类**：Reverse / 车载 ECU 固件 · UDS 诊断  
> **Flag**：`GEELY{UDS_6B2F51A7_904E96FC_MICROCODE_COLD_START}`  
> **附件**：`ecu_diag_fw.bin`（32768 字节）、`rescue_card.png`、`diagnostic_bulletin.png`、`maintenance_tool_screen.png`  
> **复现依赖**：Python 3.8+（仅标准库 `zlib`），无需 binwalk / IDA / CyberChef  
> **题面**：见 `UDS Zero.txt`

---

## 0. 题目描述与破题思路

```
一条退役诊断产线的 ECU 固件被裁剪成 32 KiB 原始切片。旧工具能识别的符号表、
服务映射和明文配置都已经被移除，只剩下一张 rescue card、一张诊断公告照片和
一次维护工具的旧屏幕截图。
不要手工重排或截断 DID 内容。解密后去除零填充，提交得到的完整字符串
flag 格式 GEELY{UDS_}
```

逐句翻译成技术要求：

| 题面 | 技术含义 |
| --- | --- |
| 32 KiB **原始切片** | 无文件头、非标准固件容器，`binwalk`/`file` 给不出结构，必须自己解析 |
| 符号表 / 服务映射 / 明文配置**已被移除** | 没有符号可查，只能靠"结构特征 + 校验和"在裸数据里定位 |
| 只剩三张图 | 线索即**规格说明书**：块格式卡 / 算法公式 / 已知测试向量 |
| **不要手工重排或截断** DID 内容 | 按给定的 `0x40` 字节整块处理，不要自行切长度或重排字节 |
| 解密后**去除零填充** | 明文尾部有 `\x00` 填充，`rstrip(b'\x00')` |

三张图的分工（这是本题设计的核心）：

```
rescue_card.png           -> 容器格式（C3 块布局 + CRC 定位法）
diagnostic_bulletin.png   -> 算法（SEED->KEY 派生公式 + DID 记录 XOR 保护 + 0x40 补零）
maintenance_tool_screen.png -> 数据（5 组 SEED:KEY 测试向量 + FINAL SEED）
```

**解题主线**：扫出 C3 块 → 取 K0..K3 / rotation / DID 偏移 → 用 5 组测试向量确认 rotation → 用 FINAL SEED 派生 KEY → 对 DID 记录重复 XOR → 去零填充得 flag。

---

## 1. 环境与基础体检

```bash
python3 -V                                  # 3.8+ 即可
cd <题目目录>
ls -l attachments/attachments/firmware attachments/attachments/maintenance_photos
```

先做体检，确认"固件体是噪声填充，flag 只在其中一小块"：

```bash
xxd -l 0x40 attachments/attachments/firmware/ecu_diag_fw.bin
file       attachments/attachments/firmware/ecu_diag_fw.bin     # -> data（无 magic）
strings -n 6 attachments/attachments/firmware/ecu_diag_fw.bin | head
# binwalk <fw>     # 可选；本环境 binwalk 可能因缺包报错，非必需
```

`strings` 输出形如 `[Jd+Au`、`xZjRYyAG`、`MW7mTn`……**全是随机可打印串**，说明固件体是高熵填充（假数据），`strings` 路线在此题无效。也正因如此，必须靠图片给出的**结构定义**去精确定位。

用纯标准库量化一下（可复现的替代 binwalk 判据）：

```python
import collections, math
d = open("attachments/attachments/firmware/ecu_diag_fw.bin", "rb").read()
ent = -sum((c/len(d))*math.log2(c/len(d)) for c in collections.Counter(d).values())
print("entropy = %.4f bits/byte" % ent)     # entropy = 7.9949 bits/byte
```

熵 `7.9949 bits/byte`（理论最大 8.0）→ 全文件近似随机，**无文件头可识别、无嵌入文件系统**，证实必须自解析结构。

---

## 2. 线索一：rescue card —— C3 块格式

`rescue_card.png` 全文（原图照抄，便于离线复现）：

```
UDS CALIBRATION RESCUE CARD / REVISION C3

BLOCK OFFSET: scan for byte C3,
then require CRC32(first 0x16 bytes) == next 4 bytes BE

 +00 08   version=C3, rotation
 +02 20   K0 (device key), BE
 +06 20   K1 (multiplier), BE
 +0A 20   K2 (final mask), BE
 +0E 20   K3 (adder), BE
 +12 20   DID record offset, BE
 +16 20   CRC32(bytes +00..+15), BE

Cyclic check is standard CRC-32/ISO-HDLC.
```

### 2.1 读表

- **定位法**：全文件扫字节 `0xC3`；对每个候选做 `CRC32(候选起 0x16 字节) == 紧跟其后的 4 字节（大端）`。这是强约束，正常只命中 1 处。
- **第二列是"位宽"**（`08`=8bit=1 字节，`20`=32bit=4 字节）。偏移按位宽累加后恰好闭合：

```
+00(1B version) +01(1B rotation) +02(4B K0) +06(4B K1) +0A(4B K2)
+0E(4B K3) +12(4B DID offset) +16(4B CRC)  =>  块总长 0x1A，CRC 覆盖前 0x16 字节
```

- **rotation 在 +01**：卡面把 `+00 08` 一行写作 `version=C3, rotation` —— 版本字节固定 `C3`，紧随的 1 字节即 `rotation`。

### 2.2 定位脚本与结果

```python
import zlib
d = open("attachments/attachments/firmware/ecu_diag_fw.bin", "rb").read()
hits = [i for i in range(len(d) - 0x1A + 1)
        if d[i] == 0xC3
        and zlib.crc32(d[i:i+0x16]) & 0xFFFFFFFF == int.from_bytes(d[i+0x16:i+0x1A], "big")]
print([hex(h) for h in hits])   # ['0x5a17']
```

> `zlib.crc32` 即 CRC-32/ISO-HDLC（反射实现，初值 `0xFFFFFFFF`、xorout `0xFFFFFFFF`），与卡面 "standard CRC-32/ISO-HDLC" 一致。

唯一命中块偏移 **0x5A17**。该处 0x1A 字节原始数据：

```
c3 0d a5 1f 3e 27 9e 37 79 b1 27 d4 eb 2f 85 eb ca 6b 00 00 7b 21 a4 e8 53 a1
```

### 2.3 字段切分表（本题最关键的一步）

| 偏移 | 字段 | 原始字节 | 值 |
| --- | --- | --- | --- |
| +00 | version | `c3` | 0xC3 |
| +01 | rotation | `0d` | **13**（0x0D） |
| +02 | K0 (device key) | `a5 1f 3e 27` | `0xA51F3E27` |
| +06 | K1 (multiplier) | `9e 37 79 b1` | `0x9E3779B1` |
| +0A | K2 (final mask) | `27 d4 eb 2f` | `0x27D4EB2F` |
| +0E | K3 (adder) | `85 eb ca 6b` | `0x85EBCA6B` |
| +12 | DID record offset | `00 00 7b 21` | **`0x7B21`** |
| +16 | CRC32 | `a4 e8 53 a1` | `0xA4E853A1` |

### ⚠️ 踩坑记录：按 4 字节对齐切分必错

若把 `+00` 起按 4 字节一组切，会得到 `K1 = 0x79B127D4`、`DID offset = 0x7B21A4E8` —— 后者 **大于 32KiB 文件长度**，物理上不可能，可当场发现错误。

两个自检手段：
1. **越界检查**：`did_off` 必须 `< len(file)`。
2. **常量直觉**：`K1 = 0x9E3779B1`、`K2 = 0x27D4EB2F` 恰是 **xxHash32 的 PRIME32_1 / PRIME32_4**（`K3 = 0x85EBCA6B` 也紧邻 PRIME32_2 `0x85EBCA77`，仅差 0x0C），说明出题人拿哈希常数做了混淆常数，也侧面印证切分正确（注意：`K3` 并非 CRC 多项式，勿混淆）。

---

## 3. 线索二：diagnostic bulletin —— 密钥派生算法

`diagnostic_bulletin.png` 全文：

```
DIAGNOSTIC BULLETIN 27-V3

Security key derivation, 32-bit unsigned:

  X = SEED xor K0
  X = (X * K1 + K3) mod 2^32
  X = X xor (X >> 15)
  X = rotate_left(X, rotation)
  X = X xor K2
  KEY = X

The DID record is repeating-XOR protected by KEY bytes.
It is zero padded to 0x40 bytes. Rotations use bit width 32.

No live ECU access is required or authorised.
```

三个要点：

1. **公式**：XOR → 乘加（`mod 2^32` 截断）→ 异或右移 15（xorshift 混淆）→ 32 位循环左移 `rotation` → 再 XOR 最终掩码。
2. **DID 记录加密方式**：`KEY` 的 **4 字节循环重复 XOR**，长度补零到 **0x40 字节**。
3. **rotation 位宽 32**：即 `rol32`，不是 8/16 位循环。rotation=0 时需特判（否则 `x >> 32` 会炸）。

Python 实现（注意 `& 0xFFFFFFFF` 处处不能省）：

```python
def rotl32(x, r):
    r &= 31
    if r == 0:
        return x & 0xFFFFFFFF
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

def derive(seed, K0, K1, K2, K3, rotation):
    M = 0xFFFFFFFF
    x = (seed ^ K0) & M              # X = SEED xor K0
    x = (x * K1 + K3) & M            # X = (X*K1 + K3) mod 2^32
    x ^= x >> 15                     # X = X xor (X >> 15)
    x = rotl32(x, rotation)          # X = rotate_left(X, rotation)
    x ^= K2                          # X = X xor K2
    return x & M                     # KEY = X
```

---

## 4. 线索三：maintenance tool screen —— 测试向量（确定 rotation）

`maintenance_tool_screen.png` 全文：

```
MAINTENANCE TOOL / OLD SESSION CACHE

SEED      KEY
11223344:43619418
2468ACE0:375AF638
5A17B3C2:4D8A7C2C
7F3E19D6:3895619F
8C0A44E2:DC270A4C

FINAL REQUESTED SEED: 6B2F51A7

DID F1A0 REMAINS LOCKED
```

这 5 组 `SEED:KEY` 是**已知明密文对**，作用是"算法确认器"：既可验证第 2.3 节的字段切分是否正确，也可把 rotation 从 32 种可能收敛到唯一值（5 组全部命中概率极低）。

```python
pairs = [(0x11223344, 0x43619418), (0x2468ACE0, 0x375AF638), (0x5A17B3C2, 0x4D8A7C2C),
         (0x7F3E19D6, 0x3895619F), (0x8C0A44E2, 0xDC270A4C)]
K0, K1, K2, K3 = 0xA51F3E27, 0x9E3779B1, 0x27D4EB2F, 0x85EBCA6B
for r in range(32):
    if all(derive(s, K0, K1, K2, K3, r) == k for s, k in pairs):
        print("rotation =", r)          # -> rotation = 13
```

结果 **rotation = 13**，与块内 `+01 = 0x0D = 13` 完全吻合 —— 三重线索自洽，证明：偏移切分正确、公式正确、字节序为大端。

> 附带确认：题面里的 `DID F1A0 REMAINS LOCKED` 是**干扰项**，F1A0 这个 DID 编号在本题解题中不需要（本题不校验 DID 号，只校验记录内容）。

---

## 5. 解密 DID 记录 → Flag

```python
SEED  = 0x6B2F51A7                          # FINAL REQUESTED SEED（截图给出）
KEY   = derive(SEED, K0, K1, K2, K3, 13)    # = 0x904E96FC
keyb  = KEY.to_bytes(4, "big")              # 大端 4 字节：90 4e 96 fc

rec   = d[0x7B21 : 0x7B21 + 0x40]           # DID 记录，固定 0x40 字节
plain = bytes(c ^ keyb[i % 4] for i, c in enumerate(rec))   # 重复 XOR
flag  = plain.rstrip(b"\x00").decode()      # 去除零填充
```

中间数据（便于逐字节核对）：

```
KEY     : 904e96fc
cipher(64B): d70bd3b0c935c3b8c311a0bea208a3cdd179c9c5a07ad3c5a608d5a3dd07d5ae
             df0dd9b8d511d5b3dc0ac9afc40fc4a8ed4e96fc904e96fc904e96fc904e96fc
plain (64B): 4745454c597b5544535f36423246353141375f39303445393646435f4d4943524f
             434f44455f434f4c445f53544152547d000000000000000000000000000000
ascii    : GEELY{UDS_6B2F51A7_904E96FC_MICROCODE_COLD_START}\0\0\0...\0
```

两条额外的正确性旁证：

- 密文**第 52~63 字节恰是 KEY 连续重复 3 次**（`rec[52:64] == 904e96fc * 3`），第 48 字节为 `0xed = 0x7d('}') ^ 0x90`。原因：明文第 49~63 字节全是补零，`0 ^ KEY = KEY`，所以密文尾部必然是 KEY 的周期序列。若 KEY 或 DID 偏移错，这里不会出现这种规律。
- 明文头部直接就是 `GEELY{`（`47 45 45 4c 59 7b`），且去零填充后长度正好闭合到 `}`。

### 🚩 Flag

```
GEELY{UDS_6B2F51A7_904E96FC_MICROCODE_COLD_START}
```

---

## 6. 一键复现

把下面完整脚本存为 `solve.py`，与附件同目录（或直接用第 7 节脚本）：

```bash
cd <题目目录>
python solve.py                 # 默认读 attachments/attachments/firmware/ecu_diag_fw.bin
python solve.py /path/to/ecu_diag_fw.bin
```

期望输出（逐行对照，任何一行不符即说明固件或脚本被改动）：

```
[*] 固件: attachments/attachments/firmware/ecu_diag_fw.bin  大小: 32768 (0x8000)
[+] C3 块 @ 0x5a17
      version   = 0xc3
      rotation  = 0xd
      K0        = 0xa51f3e27
      K1        = 0x9e3779b1
      K2        = 0x27d4eb2f
      K3        = 0x85ebca6b
      did_off   = 0x7b21
      crc       = a4e853a1
[+] 旧会话缓存验证 rotation=13: 通过
[+] SEED 0x6B2F51A7 -> KEY 904e96fc
[*] DID 记录 @ 0x7b21 (64 bytes)
      cipher  : d70bd3b0c935c3b8c311a0bea208a3cdd179c9c5a07ad3c5a608d5a3dd07d5aedf0dd9b8d511d5b3dc0ac9afc40fc4a8ed4e96fc904e96fc904e96fc904e96fc
      plain   : 4745454c597b5544535f36423246353141375f39303445393646435f4d4943524f434f44455f434f4c445f53544152547d000000000000000000000000000000
[+] FLAG: GEELY{UDS_6B2F51A7_904E96FC_MICROCODE_COLD_START}
```

脚本设计为**从固件里自行解析 K0..K3 / rotation / DID 偏移**（而不是硬编码），只有测试向量与 FINAL SEED 来自截图，因此它同时是"复现脚本"和"解法正确性的自证"。

---

## 7. 完整脚本（自包含，可直接复制运行）

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UDS Zero - CTF 复现脚本
用法:  python solve.py [ecu_diag_fw.bin]
流程:
  1) 扫描 C3 块 (CRC32/ISO-HDLC 校验)          <- rescue_card.png
  2) 解析块内 K0/K1/K2/K3/DID偏移/rotation
  3) 实现 bulletin 27-V3 的密钥派生             <- diagnostic_bulletin.png
  4) 用旧会话缓存中的 SEED:KEY 对验证 rotation  <- maintenance_tool_screen.png
  5) 对 FINAL SEED 派生 KEY, 对 DID 记录做 repeating-XOR, 去零填充
"""

import sys
import zlib

# Windows 控制台默认 GBK, 强制 UTF-8 输出避免中文乱码
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# ---------------- 旧会话缓存 (maintenance_tool_screen.png) ----------------
KNOWN_PAIRS = [
    (0x11223344, 0x43619418),
    (0x2468ACE0, 0x375AF638),
    (0x5A17B3C2, 0x4D8A7C2C),
    (0x7F3E19D6, 0x3895619F),
    (0x8C0A44E2, 0xDC270A4C),
]
FINAL_SEED = 0x6B2F51A7
DID_RECORD_LEN = 0x40  # "It is zero padded to 0x40 bytes"

def rotl32(x: int, r: int) -> int:
    """32 位循环左移 (r 位), 兼容 r=0"""
    r &= 31
    if r == 0:
        return x & 0xFFFFFFFF
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

def find_block(data: bytes) -> int:
    """扫描 byte C3, 要求 CRC32(前 0x16 字节) == 其后 4 字节 (BE)"""
    hits = []
    for i in range(len(data) - 0x1A + 1):
        if data[i] != 0xC3:
            continue
        if zlib.crc32(data[i:i + 0x16]) & 0xFFFFFFFF == \
           int.from_bytes(data[i + 0x16:i + 0x1A], "big"):
            hits.append(i)
    if not hits:
        raise SystemExit("[-] 未找到合法的 C3 块")
    if len(hits) > 1:
        print(f"[!] 命中多个块: {[hex(h) for h in hits]}, 取第一个")
    return hits[0]

def parse_block(data: bytes, off: int) -> dict:
    """
    C3 块布局 (rescue_card.png):
      +00 08  version=C3
      +01 08  rotation
      +02 20  K0 (device key),   BE
      +06 20  K1 (multiplier),   BE
      +0A 20  K2 (final mask),   BE
      +0E 20  K3 (adder),        BE
      +12 20  DID record offset, BE
      +16 20  CRC32(bytes +00..+15), BE
    """
    b = data[off:off + 0x1A]
    return {
        "block_off": off,
        "version": b[0x00],
        "rotation": b[0x01],
        "K0": int.from_bytes(b[0x02:0x06], "big"),
        "K1": int.from_bytes(b[0x06:0x0A], "big"),
        "K2": int.from_bytes(b[0x0A:0x0E], "big"),
        "K3": int.from_bytes(b[0x0E:0x12], "big"),
        "did_off": int.from_bytes(b[0x12:0x16], "big"),
        "crc": b[0x16:0x1A].hex(),
    }

def derive_key(seed: int, blk: dict, rotation: int) -> int:
    """DIAGNOSTIC BULLETIN 27-V3: Security key derivation, 32-bit unsigned"""
    M = 0xFFFFFFFF
    x = (seed ^ blk["K0"]) & M                # X = SEED xor K0
    x = (x * blk["K1"] + blk["K3"]) & M       # X = (X*K1 + K3) mod 2^32
    x ^= x >> 15                              # X = X xor (X >> 15)
    x = rotl32(x, rotation)                   # X = rotate_left(X, rotation)
    x ^= blk["K2"]                            # X = X xor K2
    return x & M

def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else \
        "attachments/attachments/firmware/ecu_diag_fw.bin"
    data = open(path, "rb").read()
    print(f"[*] 固件: {path}  大小: {len(data)} (0x{len(data):x})")

    # ---- 1) 定位 C3 块 ----
    off = find_block(data)
    blk = parse_block(data, off)
    print(f"[+] C3 块 @ 0x{off:x}")
    for k in ("version", "rotation", "K0", "K1", "K2", "K3", "did_off"):
        print(f"      {k:<9} = 0x{blk[k]:x}")
    print(f"      crc       = {blk['crc']}")

    # ---- 2) 用旧会话缓存验证 rotation ----
    rot = blk["rotation"]
    ok = all(derive_key(s, blk, rot) == k for s, k in KNOWN_PAIRS)
    print(f"[{'+' if ok else '-'}] 旧会话缓存验证 rotation={rot}: "
          f"{'通过' if ok else '失败'}")
    if not ok:
        for r in range(32):
            if all(derive_key(s, blk, r) == k for s, k in KNOWN_PAIRS):
                rot = r
                print(f"[+] 暴力校正 rotation = {r}")
                break
        else:
            raise SystemExit("[-] rotation 无法确定")

    # ---- 3) FINAL SEED -> KEY ----
    key = derive_key(FINAL_SEED, blk, rot).to_bytes(4, "big")
    print(f"[+] SEED 0x{FINAL_SEED:08X} -> KEY {key.hex()}")

    # ---- 4) repeating-XOR 解密 DID 记录, 去零填充 ----
    rec = data[blk["did_off"]:blk["did_off"] + DID_RECORD_LEN]
    plain = bytes(c ^ key[i % 4] for i, c in enumerate(rec))
    flag = plain.rstrip(b"\x00")

    print(f"[*] DID 记录 @ 0x{blk['did_off']:x} ({len(rec)} bytes)")
    print(f"      cipher  : {rec.hex()}")
    print(f"      plain   : {plain.hex()}")
    print(f"[+] FLAG: {flag.decode(errors='replace')}")

if __name__ == "__main__":
    main()
```

---

## 8. 思路复盘 / 可复用方法论

1. **先读"元线索"（图片/截图/日志），再动固件。** 逆向 CTF 里图片往往不是干扰项而是**规格说明书**。本题三张图分别给出 *容器格式*、*算法公式*、*已知测试向量*，三者交叉自洽 —— 这是题目可解性的保证。
2. **二进制块定位优先用校验和，而非特征字符串。** 固件体为高熵噪声时 `strings` 全是垃圾；而 `byte==0xC3 && CRC32(0x16) == next4(BE)` 这类约束几行代码即可全盘扫描，命中唯一、零误报。
3. **按"位宽表"推进偏移，警惕起始对齐陷阱。** 唯一踩坑：从 `+00` 起按 4 字节对齐切分，导致偏移字段越界。**用物理合理性当断言**（`did_off < len(file)`）能瞬间暴露错误。
4. **已知明密文对是算法确认器。** 5 组 `SEED:KEY` 既验证公式，也把 rotation 从 32 种可能收敛到唯一值。没有它们，会得到 32 个候选明文而无法裁决。
5. **成功要有旁证，而不是"看起来像"。** 本题的旁证有三个：明文尾部 `\x00` 补零（题面也提示"去除零填充"）、密文尾部 KEY 周期性重复、明文头部直出 `GEELY{` 且去零后长度恰好闭合。
6. **注意题面的反向提示。** "不要手工重排或截断 DID 内容" = 直接按 `0x40` 整块处理，不要自作聪明改长度/重排；"32 KiB 原始切片" = 别指望 binwalk。
7. **脚本应"从附件自行解析"而非硬编码常量。** 这样脚本本身即是解法正确性的自证：K0..K3、rotation、DID 偏移全部由固件解析得出，只有测试向量和 FINAL SEED 来自截图，两者一旦不一致脚本会报错。

---

## 9. 附：UDS 知识点对照（本题借壳，非真实协议交互）

| 题目元素 | 真实 UDS 对应 |
| --- | --- |
| DID / `DID F1A0` | `0x22 ReadDataByIdentifier`、`0x2E WriteDataByIdentifier` 的数据标识符 |
| SEED / KEY 派生 | `0x27 SecurityAccess`：ECU 出 SEED，诊断仪回 KEY；现实中为厂商私有派生算法（本题用哈希常数 + XOR/乘加/移位/循环移位混淆） |
| `No live ECU access is required` | 纯离线静态分析即可，无需模拟 CAN / DoIP 会话 |
| `DID F1A0 REMAINS LOCKED` | 干扰项；本题不需要解锁握手，只解静态记录 |
