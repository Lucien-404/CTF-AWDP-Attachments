# CAN Noir — WriteUp（自包含复现版）

> **分类**：Automotive / CAN 总线逆向 · 无钥匙进入（PEPS）滚动码
> **Flag**：`GEELY{CAN_c5007c61406904bf_f65dc5131e39daea}`
> **一句话**：照片取色卡得 K/M/S/R → 用日志 8 帧验证变换 → 推出第 9 帧 `18FF50A5#00487D409043D771` → 对数据段大写 hex 取 sha256，取**前 16 位 + 末 16 位**。
> **本文件可独立复现**：解题脚本全文、命令、原始数据说明、期望输出全部内嵌，只需配合原始附件 `attachments/` 即可复现。

---

## 0. 题目原文

### 0.1 题目内容（`题目内容.txt`）

```
一把无钥匙进入钥匙的配置区已被返修时擦除，只剩下 PCB 返修照片、厂商色卡和一段总线记录。
记录里有 8 次已接受的解锁帧，但下一帧没有捕获。
flag格式GEELY{CAN_<sha256前16位>_<sha256后16位>}
```

### 0.2 附件（`attachments.zip` 解压后）

```
CAN Noir/
├── attachments/attachments/
│   ├── can_signal_notes.txt                     # 报文布局说明
│   ├── can_unlock_trace.log                     # 8 条已接受的解锁帧
│   ├── field_service_extract.txt                # 32-bit 变换公式
│   └── maintenance_photos/
│       ├── keyless_pcb.png     (1020x680)       # 返修板照片：R1~R8 色块 + U1 丝印 + 旋转级
│       └── decode_card.png     (760x330)        # 厂商色卡：16 个色块 = nibble 0..F
├── decode_colors.py                             # 步骤 1（附录 A）
├── solve.py                                     # 步骤 2~4（附录 B）
├── try_flags.py                                 # 序列化方式对照（附录 C，可选）
└── WP.md                                        # 本文
```

> ⚠️ 注意 zip 解压后有**两层同名 `attachments/`**，脚本里的相对路径按上表写。

---

## 1. 环境与目录

```bash
python3 -V                 # 3.8+（实测 3.13 亦可）
pip install pillow         # 只有 decode_colors.py 需要；solve.py 仅用标准库
```

脚本里的路径是**相对当前工作目录**的，因此必须在 `CAN Noir/` 目录下运行：

```bash
cd "CAN Noir"
python decode_colors.py
python solve.py
```

---

## 2. 分析总览

```
keyless_pcb.png ──┐
                  ├─(附录A：像素定点取色)──> K=0x49AF32C7  M=0x5A17C0DE  S=0x9E3779B1  R=7
decode_card.png ──┘                                                                     │
                                                                                        ▼
can_unlock_trace.log ──(8 条帧 N=0x40..0x47)──────────────> 用公式复算 8/8 命中，参数确认
                                                                                        │
                                                                                        ▼
                                          N=0x48 ──(附录B：token + 组帧)──> 00 48 7D 40 90 43 D7 71
                                                                                        │
                                                                                        ▼
                          sha256("00487D409043D771" 大写) ──> 取 h[:16] + h[-16:] ──> FLAG
```

三个文件的分工：

| 文件 | 提供的信息 |
| --- | --- |
| `decode_card.png` | 颜色 → nibble(0..F) 的映射表 |
| `keyless_pcb.png` | R1~R8 色块（→ K/M）、U1 丝印 `9E37`+`79B1`（→ S）、7 个三角（→ R） |
| `field_service_extract.txt` | 32-bit 变换公式（K/S/M/R/N → T） |
| `can_signal_notes.txt` | 8 字节数据段布局 + 计数器递增规则 |
| `can_unlock_trace.log` | 8 条已接受帧（用于**验证**参数，也用于确认计数器起点） |

---

## 3. 步骤 1：照片 → 参数

### 3.1 色卡：16 个色块 = nibble 0..F

`decode_card.png` 是白底、2 行 × 8 列色块，色块尺寸约 54×38。
用像素实测得：**色块中心列 x = 67, 155, 243, 331, 419, 507, 595, 683**；
**两行中心行 y = 100 / 170**（第二行色块恰好被数字标签白底包住，所以只能定点取色）。

按「左 → 右、上 → 下 = 0..F」依次取色，得到映射：

| RGB | nibble | 颜色 | RGB | nibble | 颜色 |
| --- | --- | --- | --- | --- | --- |
| `(0,0,0)` | **0** | 黑 | `(141,141,141)` | **8** | 灰 |
| `(123,74,18)` | **1** | 棕 | `(255,255,255)` | **9** | 白 |
| `(221,34,34)` | **2** | 红 | `(200,117,51)` | **A** | 土黄 |
| `(255,136,0)` | **3** | 橙 | `(216,216,216)` | **B** | 浅灰 |
| `(255,230,128)` | **4** | 黄 | `(224,64,192)` | **C** | 品红 |
| `(28,138,58)` | **5** | 绿 | `(0,183,208)` | **D** | 青 |
| `(32,96,208)` | **6** | 蓝 | `(128,128,0)` | **E** | 橄榄 |
| `(138,78,208)` | **7** | 紫 | `(0,32,128)` | **F** | 藏蓝 |

> ⚠️ 白色 9 的 RGB 与卡片白底相同 → **不要用"自动找色块"的办法**，会漏掉 9 和 B；必须定点取色。

### 3.2 PCB：两条色块带 → R1..R8

`keyless_pcb.png` 是 1020×680 绿底（`(23,129,94)`）板子。
色块贴在土黄底座 `(217,201,163)` 上，上下两条带：
**R1~R4 带中心行 y = 140；R5~R8 带中心行 y = 300**。

沿中心行做**游程扫描**，只保留「颜色能在色卡字典里查到」且宽度 > 20px 的色块
（这一条过滤规则同时滤掉了绿底和土黄底座），再按 x 排序两两配对：

| 位置 | 色块（左 / 右） | hex |
| --- | --- | --- |
| R1 | 黄 `4` / 白 `9` | `49` |
| R2 | 土黄 `A` / 藏蓝 `F` | `AF` |
| R3 | 橙 `3` / 红 `2` | `32` |
| R4 | 品红 `C` / 紫 `7` | `C7` |
| R5 | 绿 `5` / 土黄 `A` | `5A` |
| R6 | 棕 `1` / 紫 `7` | `17` |
| R7 | 品红 `C` / 黑 `0` | `C0` |
| R8 | 青 `D` / 橄榄 `E` | `DE` |

### 3.3 U1 与旋转级

```
U1   9E37        →  S = 0x9E3779B1    （两行丝印拼成 32 位，恰为常见黄金比常数）
     79B1

ROTATION STAGE  ▷ ▷ ▷ ▷ ▷ ▷ ▷        →  7 个二极管三角  →  R = 7
```

### 3.4 参数汇总

| 参数 | 值 | 来源 |
| --- | --- | --- |
| K | `0x49AF32C7` | R1..R4（nibble 对拼接） |
| M | `0x5A17C0DE` | R5..R8 |
| S | `0x9E3779B1` | U1 丝印 |
| R | `7` | 旋转级三角个数 |
| CAN ID | `18FF50A5` | `can_signal_notes.txt` |
| phase | `0x7D` | 8 条日志中的 byte2（固定） |

### 3.5 用脚本自动得到这些数

运行附录 A 的 `decode_colors.py`（`python decode_colors.py`），期望输出：

```
=== 色卡 RGB -> nibble ===
  (0, 0, 0)          -> 0
  (123, 74, 18)      -> 1
  (221, 34, 34)      -> 2
  (255, 136, 0)      -> 3
  (255, 230, 128)    -> 4
  (28, 138, 58)      -> 5
  (32, 96, 208)      -> 6
  (138, 78, 208)     -> 7
  (141, 141, 141)    -> 8
  (255, 255, 255)    -> 9
  (200, 117, 51)     -> A
  (216, 216, 216)    -> B
  (224, 64, 192)     -> C
  (0, 183, 208)      -> D
  (128, 128, 0)      -> E
  (0, 32, 128)       -> F

=== PCB 色块 -> nibble ===
  R1 = 0x49
  R2 = 0xAF
  R3 = 0x32
  R4 = 0xC7
  R5 = 0x5A
  R6 = 0x17
  R7 = 0xC0
  R8 = 0xDE

K (R1..R4) = 0x49AF32C7
M (R5..R8) = 0x5A17C0DE
S (U1 丝印 9E37 79B1) = 0x9E3779B1
R (ROTATION STAGE 三角数) = 7
```

---

## 4. 步骤 2：变换公式与 8/8 校验

### 4.1 公式（`field_service_extract.txt`）

```
X = K xor (N * S)         # 32-bit 无符号
X = rotate_left(X, R)
X = X xor M
T = X xor (X >> 13)       # 扩散：异或右移 13
```

### 4.2 数据段布局（`can_signal_notes.txt`）

```
byte 0 : counter high          byte 4 : rolling token byte 2
byte 1 : counter low           byte 5 : rolling token byte 1
byte 2 : fixed phase marker    byte 6 : rolling token byte 0
byte 3 : rolling token byte 3  byte 7 : XOR of byte 0 through byte 6
      ↑ token 大端；计数器每次 +1；重放被拒
```

### 4.3 实现（32 位截断是成败关键）

```python
MASK = 0xFFFFFFFF
def rol(x, n): return ((x << n) | (x >> (32 - n))) & MASK

def token(n):
    x = (K ^ ((n * S) & MASK)) & MASK     # ← (N*S) 必须先截断成 32 位
    x = rol(x, R)
    x ^= M
    return (x ^ (x >> 13)) & MASK
```

### 4.4 用日志 8 帧验证（三重比对：token、phase、byte7 异或）

| N | 日志 token | 计算 token | phase | byte7 | 结果 |
| --- | --- | --- | --- | --- | --- |
| 0x40 | `62BB96F8` | `62BB96F8` | 0x7d | 0x8a | OK |
| 0x41 | `8778600E` | `8778600E` | 0x7d | 0xad | OK |
| 0x42 | `AB242B14` | `AB242B14` | 0x7d | 0x8f | OK |
| 0x43 | `CFE475DE` | `CFE475DE` | 0x7d | 0xbe | OK |
| 0x44 | `D3A1BC40` | `D3A1BC40` | 0x7d | 0xb7 | OK |
| 0x45 | `F46F5AEF` | `F46F5AEF` | 0x7d | 0x16 | OK |
| 0x46 | `182D5137` | `182D5137` | 0x7d | 0x68 | OK |
| 0x47 | `3CEF4FFF` | `3CEF4FFF` | 0x7d | 0x59 | OK |

**8 条 × 32 bit 全部命中** → K/M/S/R 与出题人完全一致，可以放心外推下一帧。

> 这一步不能跳过：如果 `(N*S)` 忘了截断 32 位，因为后续 `X >> 13` 会把高位带进结果，
> 8 条会全部 MISMATCH，正好用来自查。

---

## 5. 步骤 3：预测第 9 帧

计数器在日志里是 `0x40 → 0x47`，规则 "Accepted counters increase by one" → **下一帧 `N = 0x48`**。

```python
def build(n):
    t = token(n)
    b = bytes([(n >> 8) & 0xFF, n & 0xFF, 0x7D]) + t.to_bytes(4, "big")   # 大端
    chk = 0
    for c in b[:7]:
        chk ^= c
    return b + bytes([chk])
```

结果：

```
token(0x48)  = 0x409043D7
data 8 bytes = 00 48 7D 40 90 43 D7 71
完整帧       = 18FF50A5#00487D409043D771
（byte7 校验 = 00^48^7D^40^90^43^D7 = 0x71）
```

### 5.1 逐步手算复核（可与脚本输出对齐）

```
n  = 0x48
K  = 0x49AF32C7   M = 0x5A17C0DE   S = 0x9E3779B1   R = 7

n*S                 = 0x2C7F9A39C8
(n*S) & 0xFFFFFFFF  = 0x7F9A39C8          ← 必须截断 32 位
X1 = K ^ 上值       = 0x36350B0F
X2 = ROL(X1, 7)     = 0x1A85879B
X3 = X2 ^ M         = 0x40924745
T  = X3 ^ (X3>>13)  = 0x40924745 ^ 0x20492 = 0x409043D7   ← 与脚本一致
```

### 5.2 组帧

```
byte0 = N>>8          = 0x00
byte1 = N&0xFF        = 0x48
byte2 = phase         = 0x7D
byte3..6 = T 大端     = 40 90 43 D7
byte7 = XOR(byte0..6) = 0x71

=> 数据段 = 00 48 7D 40 90 43 D7 71
=> 完整帧 = 18FF50A5#00487D409043D771
```

---

## 6. 步骤 4：出 flag

题目：`GEELY{CAN_<sha256前16位>_<sha256后16位>}`。
sha256 的输入是**数据段的 8 字节大写 hex 字符串**（与日志中 `#` 后面的写法一致）：

```python
import hashlib
h = hashlib.sha256("00487D409043D771".encode()).hexdigest()
# c5007c61406904bff895b0b55e5d48c32ec010ff03bc7f79f65dc5131e39daea
flag = f"GEELY{{CAN_{h[:16]}_{h[-16:]}}}"
```

```
digest = c5007c61406904bf f895b0b55e5d48c3 2ec010ff03bc7f79 f65dc5131e39daea
         └── 前16位 ──┘ └─────── 中间 32 位，丢弃 ────────┘ └── 后16位 ──┘
         h[:16]           h[16:48]                        h[-16:] (= h[48:])
```

## 🚩 Flag

```
GEELY{CAN_c5007c61406904bf_f65dc5131e39daea}
```

---

## 7. 踩坑记录

### 7.1 `sha256后16位` = `h[-16:]`，不是 `h[16:]`  ★★★（本题唯一失分点）

第一次把「后 16 位」理解成「从第 17 位开始到结尾」，取 `h[16:]`（48 个字符）当第二段，
得到 `GEELY{CAN_c5007c61406904bf_f895b0b55e5d48c32ec010ff03bc7f79f65dc5131e39daea}`，flag 被判错。
正确是 **首 16 位 + 末 16 位**：

```python
f"GEELY{{CAN_{h[:16]}_{h[-16:]}}}"      # ✅ 正确
f"GEELY{{CAN_{h[:16]}_{h[16:]}}}"       # ❌ 错误（中间 32 位）
```

这也是 flag 模板中间那个下划线的含义：把 64 位摘要「掐头去尾」成两段。

### 7.2 色卡必须按 RGB 精确比对

「棕 1 / 橙 3 / 土黄 A」以及「黄 4 / 白 9」「灰 8 / 浅灰 B」肉眼极易看混；
白 9 与卡片白底同色，**只能用定点取色**，不能靠找色块。

### 7.3 时间戳是干扰项

日志时间戳严格等差（相邻间隔 3.430 / 3.456 / 3.482 / … 每次 +0.026s），
按此规律可外推出第 9 帧时间戳 = `1789601024.556 + 3.612 = 1789601028.168`，
很容易诱导做题者把「完整 candump 行（含时间戳）」当哈希输入。
**实际 sha256 只对 8 字节数据段转成的 16 位大写 hex 字符串取**，
与时间戳、接口名 `can1`、CAN ID、`DLC` 都无关；
若误按整行哈希，会得到 `GEELY{CAN_3de61ff294983be0_63044ac7fd167b29}`（错误，见附录 C 第 6 项对照）。

### 7.4 `(N*S)` 必须截断 32 位

`N*S` 是 64 位结果，若先不截断就异或、再旋转，`X >> 13` 会把高位带进结果。
用日志 8 帧做校验即可立刻发现。

### 7.5 脚本工作目录

脚本用相对路径读 `attachments/attachments/...`，必须在 `CAN Noir/` 下运行，
否则会 `FileNotFoundError`。

---

## 8. 完整复现步骤（从零开始）

### 8.1 解压附件

```bash
cd "CAN Noir"
unzip -o attachments.zip -d attachments      # 解出 attachments/attachments/...
ls -R attachments
```

期望看到：

```
attachments/attachments/can_signal_notes.txt
attachments/attachments/can_unlock_trace.log
attachments/attachments/field_service_extract.txt
attachments/attachments/maintenance_photos/decode_card.png
attachments/attachments/maintenance_photos/keyless_pcb.png
```

### 8.2 落盘两个脚本

把 **附录 A** 的代码整段保存为 `decode_colors.py`，把 **附录 B** 的代码整段保存为 `solve.py`
（附录 C 的 `try_flags.py` 可选）。也可以直接用 heredoc：

```bash
# 附录 A 源码
cat > decode_colors.py <<'PY'
...（复制附录 A 全文）...
PY

# 附录 B 源码
cat > solve.py <<'PY'
...（复制附录 B 全文）...
PY
```

安装依赖（只影响步骤 1）：

```bash
pip install pillow
```

### 8.3 运行

```bash
python decode_colors.py     # 步骤 1：照片 → K/M/S/R
python solve.py             # 步骤 2~4：验证 + 预测 + 出 flag
```

`solve.py` 期望输出（与本 WP 完全一致）：

```
==============================================================
步骤 2：复算日志 8 条已接受帧（校验 K/M/S/R 是否正确）
==============================================================
   N   日志 token   计算 token  phase   xor  结果
0040   62BB96F8   62BB96F8   0x7d  0x8a  OK
0041   8778600E   8778600E   0x7d  0xad  OK
0042   AB242B14   AB242B14   0x7d  0x8f  OK
0043   CFE475DE   CFE475DE   0x7d  0xbe  OK
0044   D3A1BC40   D3A1BC40   0x7d  0xb7  OK
0045   F46F5AEF   F46F5AEF   0x7d  0x16  OK
0046   182D5137   182D5137   0x7d  0x68  OK
0047   3CEF4FFF   3CEF4FFF   0x7d  0x59  OK
[+] 8/8 全部匹配 -> K/M/S/R 参数与题目一致

==============================================================
步骤 3：预测下一帧（计数器 0x40..0x47 -> 0x48）
==============================================================
  token(0x48)   = 0x409043d7
  data 8 bytes  = 00 48 7D 40 90 43 D7 71
  完整帧        = 18FF50A5#00487D409043D771
  （校验字节 byte7 = XOR(byte0..6) = 0x71）

==============================================================
步骤 4：sha256(数据段大写 hex) -> flag
==============================================================
  sha256(00487D409043D771)
        = c5007c61406904bff895b0b55e5d48c32ec010ff03bc7f79f65dc5131e39daea
  前16位 = c5007c61406904bf
  后16位 = f65dc5131e39daea

[+] FLAG: GEELY{CAN_c5007c61406904bf_f65dc5131e39daea}

-- 其他序列化方式对照（非本题答案） --
  18FF50A5#00487D409043D771  GEELY{CAN_2d473fd9b0616d93_52b306fb937fca0f}
  bytes                      GEELY{CAN_8a663785962c9a67_8c45eed5b4fd503c}
  00487d409043d771           GEELY{CAN_c99276b6468e2122_41060ddd01210ae2}
```

### 8.4 不装 pillow 的极简复现（纯标准库，直接出 flag）

如果只想最快拿到 flag，把下面整段存成 `quick.py` 执行即可（参数已从照片读出并写死；
`decode_colors.py` 负责证明这些参数确实来自照片，`solve.py` 会用日志 8 帧再自校验一遍）：

```python
import hashlib

K, M, S, R = 0x49AF32C7, 0x5A17C0DE, 0x9E3779B1, 7
MASK = 0xFFFFFFFF


def rol(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK


def token(n):
    x = (K ^ ((n * S) & MASK)) & MASK      # X = K xor (N*S) 截断 32 位
    x = rol(x, R)                          # X = ROL(X, R)
    x ^= M                                 # X = X xor M
    return (x ^ (x >> 13)) & MASK          # T = X xor (X >> 13)


n = 0x48
T = token(n)
data = bytes([n >> 8, n & 0xFF, 0x7D]) + T.to_bytes(4, "big")   # 大端
chk = 0
for c in data[:7]:
    chk ^= c
data += bytes([chk])

print("token  =", hex(T))
print("data   =", " ".join(f"{c:02X}" for c in data))
print("frame  =", "18FF50A5#" + data.hex().upper())

h = hashlib.sha256(data.hex().upper().encode()).hexdigest()
print("sha256 =", h)
print("flag   = GEELY{CAN_%s_%s}" % (h[:16], h[-16:]))
```

期望输出：

```
token  = 0x409043d7
data   = 00 48 7D 40 90 43 D7 71
frame  = 18FF50A5#00487D409043D771
sha256 = c5007c61406904bff895b0b55e5d48c32ec010ff03bc7f79f65dc5131e39daea
flag   = GEELY{CAN_c5007c61406904bf_f65dc5131e39daea}
```

---

## 附录 A：`decode_colors.py` 完整源码

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CAN Noir —— 步骤 1：从两张照片里把 nibble 读出来（不靠肉眼，可复现）

依赖：pip install pillow
用法：python decode_colors.py      （必须在题目根目录 CAN Noir/ 下运行）

做法：
  1) decode_card.png（厂商色卡，760x330）：2 行 x 8 列共 16 个约 54x38 的色块，
     色块中心列 x = 67,155,243,331,419,507,595,683；两行中心行 y = 100 / 170。
     直接在这 16 个固定点取 RGB，即得 RGB -> nibble(0..F) 字典。
     （白色 9 的 RGB 与白底相同，所以必须定点取色，不能用“找色块”的办法。）
  2) keyless_pcb.png（1020x680）：上下两条色块带（R1..R4 在 y=140，R5..R8 在 y=300），
     沿中心行做游程扫描得到每个色块的 RGB，再查字典。
"""
from PIL import Image

CARD = "attachments/attachments/maintenance_photos/decode_card.png"
PCB = "attachments/attachments/maintenance_photos/keyless_pcb.png"

CARD_COLS = [67, 155, 243, 331, 419, 507, 595, 683]   # 8 列色块中心
CARD_ROWS = [100, 170]                                 # 2 行色块中心
PCB_ROWS = [140, 300]                                  # 两条色块带中心行


def build_palette():
    """色卡 16 个定点取色 -> {RGB: '0'..'F'}（左到右、上到下依次 0..F）"""
    px = Image.open(CARD).convert("RGB").load()
    pal, nib = {}, 0
    for y in CARD_ROWS:
        for x in CARD_COLS:
            pal[px[x, y]] = f"{nib:X}"
            nib += 1
    return pal


def scan_band(img, y, pal):
    """沿 y 行做游程扫描，只保留“颜色能在色卡里查到”且足够宽的色块。
    这样可自动滤掉板子绿底(23,129,94)和色块底座土黄(217,201,163)。"""
    W, _ = img.size
    px = img.load()
    out, prev, start = [], None, 0
    for x in range(W):
        c = px[x, y]
        if c != prev:
            if prev is not None and prev in pal and x - start > 20:
                out.append((prev, start, x - 1))
            prev, start = c, x
    if prev is not None and prev in pal and W - start > 20:
        out.append((prev, start, W - 1))
    return out


def decode_pcb(pal):
    img = Image.open(PCB).convert("RGB")
    res = {}
    for row, y in enumerate(PCB_ROWS):
        sw = scan_band(img, y, pal)
        sw.sort(key=lambda t: t[1])         # 按 x 排序
        for i in range(0, len(sw), 2):      # 每个 R 两个色块
            r_no = row * 4 + i // 2 + 1
            a, b = pal[sw[i][0]], pal[sw[i + 1][0]]
            res[f"R{r_no}"] = a + b
    return res


if __name__ == "__main__":
    pal = build_palette()
    print("=== 色卡 RGB -> nibble ===")
    for c, n in sorted(pal.items(), key=lambda kv: int(kv[1], 16)):
        print(f"  {str(c):18s} -> {n}")

    pcb = decode_pcb(pal)
    print("\n=== PCB 色块 -> nibble ===")
    for k in sorted(pcb, key=lambda s: int(s[1:])):
        print(f"  {k} = 0x{pcb[k]}")

    K = "".join(pcb[f"R{i}"] for i in range(1, 5))
    M = "".join(pcb[f"R{i}"] for i in range(5, 9))
    print(f"\nK (R1..R4) = 0x{K}")
    print(f"M (R5..R8) = 0x{M}")
    print("S (U1 丝印 9E37 79B1) = 0x9E3779B1")
    print("R (ROTATION STAGE 三角数) = 7")
```

---

## 附录 B：`solve.py` 完整源码

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CAN Noir —— 无钥匙进入滚动 token 还原 + 下一帧预测（一键复现）

题目：GEELY{CAN_<sha256前16位>_<sha256后16位>}
      sha256 输入 = 第 9 帧数据段的【大写 hex 字符串】
      注意 "后16位" = digest[-16:]（最后 16 位），不是 digest[16:]

流程：
  1) 读照片取参数（decode_colors.py 自动化；这里写死解码结果并用日志 8 帧自校验）
  2) 按 field_service_extract.txt 的公式复算日志里 8 条已接受帧 —— 验证参数
  3) 预测第 9 帧（N = 0x48）的完整 8 字节数据段
  4) 对数据段大写 hex 字符串取 sha256，拼出 flag

仅依赖标准库。
"""
import hashlib

# ============ 步骤 1：照片 -> 参数（decode_colors.py 的输出） ============
# R1: 4 9   R2: A F   R3: 3 2   R4: C 7
# R5: 5 A   R6: 1 7   R7: C 0   R8: D E
K = 0x49AF32C7          # R1..R4 nibble pairs
M = 0x5A17C0DE          # R5..R8 nibble pairs
S = 0x9E3779B1          # U1 丝印: 9E37 + 79B1
R = 7                   # ROTATION STAGE 的二极管三角个数
MASK = 0xFFFFFFFF

CAN_ID = "18FF50A5"     # can_signal_notes.txt
PHASE = 0x7D            # byte2 固定相位标记
NEXT_N = 0x48           # 日志计数器 0x40..0x47，"increase by one" -> 下一帧 0x48

# ============ 日志：8 条已接受的解锁帧（can_unlock_trace.log） ============
LOG = [
    "00407D62BB96F88A", "00417D8778600EAD", "00427DAB242B148F", "00437DCFE475DEBE",
    "00447DD3A1BC40B7", "00457DF46F5AEF16", "00467D182D513768", "00477D3CEF4FFF59",
]


def rol(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK


def token(n):
    """32-bit unsigned 滚动令牌变换：
       X = K xor (N*S); X = ROL(X,R); X = X xor M; T = X xor (X>>13)"""
    x = (K ^ ((n * S) & MASK)) & MASK
    x = rol(x, R)
    x ^= M
    x = (x ^ (x >> 13)) & MASK
    return x


def build(n):
    """构造 8 字节 CAN 数据段: [cntHi][cntLo][phase][T(4,BE)][xor of byte0..6]"""
    t = token(n)
    b = bytes([(n >> 8) & 0xFF, n & 0xFF, PHASE]) + t.to_bytes(4, "big")
    chk = 0
    for c in b[:7]:
        chk ^= c
    return b + bytes([chk])


def flag_of(data, h=None):
    """GEELY{CAN_<sha256前16位>_<sha256后16位>}
       - digest[:16]  = 前16位
       - digest[-16:] = 后16位   ← 关键！不是 digest[16:]"""
    if h is None:
        b = data if isinstance(data, bytes) else data.encode()
        h = hashlib.sha256(b).hexdigest()
    return f"GEELY{{CAN_{h[:16]}_{h[-16:]}}}", h


# ============ 步骤 2：用 8 条日志验证参数 ============
def verify():
    print("=" * 62)
    print("步骤 2：复算日志 8 条已接受帧（校验 K/M/S/R 是否正确）")
    print("=" * 62)
    print(f"{'N':>4} {'日志 token':>10} {'计算 token':>10} {'phase':>6} {'xor':>5}  结果")
    for line in LOG:
        b = bytes.fromhex(line)
        n = (b[0] << 8) | b[1]
        t_log = int.from_bytes(b[3:7], "big")
        t_calc = token(n)
        chk = 0
        for c in b[:7]:
            chk ^= c
        ok = (t_calc == t_log) and (b[2] == PHASE) and (chk == b[7])
        print(f"{n:04X} {t_log:>10X} {t_calc:>10X} {b[2]:>#6x} {b[7]:>#5x}  "
              f"{'OK' if ok else 'MISMATCH'}")
        if not ok:
            raise SystemExit("[!] 参数不正确！")
    print("[+] 8/8 全部匹配 -> K/M/S/R 参数与题目一致\n")


# ============ 步骤 3/4：预测下一帧并出 flag ============
def main():
    verify()

    print("=" * 62)
    print("步骤 3：预测下一帧（计数器 0x40..0x47 -> 0x48）")
    print("=" * 62)
    nxt = build(NEXT_N)
    hex_up = nxt.hex().upper()
    print(f"  token({NEXT_N:#04x})   = {token(NEXT_N):#010x}")
    chk = 0
    for c in nxt[:7]:
        chk ^= c
    print(f"  data 8 bytes  = {' '.join(f'{c:02X}' for c in nxt)}")
    print(f"  完整帧        = {CAN_ID}#{hex_up}")
    print(f"  （校验字节 byte7 = XOR(byte0..6) = {chk:#04x}）\n")

    print("=" * 62)
    print("步骤 4：sha256(数据段大写 hex) -> flag")
    print("=" * 62)
    flag, h = flag_of(hex_up)
    print(f"  sha256({hex_up})")
    print(f"        = {h}")
    print(f"  前16位 = {h[:16]}")
    print(f"  后16位 = {h[-16:]}")
    print(f"\n[+] FLAG: {flag}")

    # 其他序列化方式（仅对照，题目用的是上面第一行）
    print("\n-- 其他序列化方式对照（非本题答案） --")
    for tag, data in [(f"{CAN_ID}#{hex_up}", f"{CAN_ID}#{hex_up}"),
                      ("bytes", nxt),
                      (hex_up.lower(), hex_up.lower())]:
        f2, h2 = flag_of(data)
        print(f"  {tag:26s} {f2}")


if __name__ == "__main__":
    main()
```

---

## 附录 C：`try_flags.py` 完整源码

排错用：把所有合理的 sha256 序列化方式都算一遍（本题答案是**列表里的第 8 项**）。

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CAN Noir —— 下一帧已 100% 确定：18FF50A5#00487D409043D771
（K=0x49AF32C7 M=0x5A17C0DE S=0x9E3779B1 R=7，用日志中 8 条记录全部复算通过）

题目只写了 "sha256前16位_sha256后16位"，没写 sha256 的输入怎么序列化。
下面把合理的序列化方式全部列出，按可能性排序 —— 逐个提交即可。
"""
import hashlib

CAN_ID = "18FF50A5"
P_U = "00487D409043D771"      # 第 9 帧数据段 N=0x48
P_L = P_U.lower()
raw8 = bytes.fromhex(P_U)
raw12 = bytes.fromhex(CAN_ID) + raw8
tok = raw8[3:7]               # 0x409043D7
LINE = "(1789601028.168000) can1 18FF50A5#00487D409043D771"   # 时间戳按 +0.026s 递增推得

CANDS = [
    ("1) 整帧字符串，与日志同格式(大写)",   f"{CAN_ID}#{P_U}"),
    ("2) 数据段 8 字节原始二进制",           raw8),
    ("3) 数据段 hex 小写 (bytes.hex())",     P_L),
    ("4) ID+数据段 12 字节原始二进制",       raw12),
    ("5) 整帧字符串小写",                    f"{CAN_ID.lower()}#{P_L}"),
    ("6) 完整 candump 行(含推算时间戳)",     LINE),
    ("7) ID+数据 无'#' 大写",                CAN_ID + P_U),
    ("8) 数据段 hex 大写(本题答案)",         P_U),
    ("9) 数据段 hex 大写 + 换行",            P_U + "\n"),
    ("10) 'can1 ' + 整帧字符串",             f"can1 {CAN_ID}#{P_U}"),
    ("11) 滚动令牌 4 字节",                  tok),
    ("12) 滚动令牌 hex 大写",                tok.hex().upper()),
]


def flag_of(data):
    # 注意："sha256后16位" = digest[-16:]（最后16位），不是 digest[16:]
    b = data if isinstance(data, bytes) else data.encode()
    h = hashlib.sha256(b).hexdigest()
    return f"GEELY{{CAN_{h[:16]}_{h[-16:]}}}"


if __name__ == "__main__":
    for tag, d in CANDS:
        shown = d if isinstance(d, str) else d.hex(" ")
        print(f"{tag:34s} sha256({shown})")
        print(f"    {flag_of(d)}")
```

运行结果（前 8 项）：

| # | sha256 输入 | flag |
| --- | --- | --- |
| 1 | `18FF50A5#00487D409043D771` | `GEELY{CAN_2d473fd9b0616d93_52b306fb937fca0f}` |
| 2 | 8 字节原始二进制 | `GEELY{CAN_8a663785962c9a67_8c45eed5b4fd503c}` |
| 3 | `00487d409043d771`（小写） | `GEELY{CAN_c99276b6468e2122_41060ddd01210ae2}` |
| 4 | ID+数据 12 字节二进制 | `GEELY{CAN_c92c20c8158d6fd8_b5f9d5e4da2cf94d}` |
| 5 | `18ff50a5#00487d409043d771` | `GEELY{CAN_1063ec5ded30482d_6b48ba18d145a212}` |
| 6 | 含推算时间戳的整行 | `GEELY{CAN_3de61ff294983be0_63044ac7fd167b29}` |
| 7 | `18FF50A500487D409043D771` | `GEELY{CAN_c4d530ecc144c21b_a09c95ed4c05d806}` |
| **8** | **`00487D409043D771`（大写）← 本题答案** | **`GEELY{CAN_c5007c61406904bf_f65dc5131e39daea}`** |

---

## 附录 D：附件哈希校验

| 文件 | MD5 | SHA256 |
| --- | --- | --- |
| can_signal_notes.txt | `f1000f1e36f5b33f4e165f62fdf7f927` | `2cfedbb14ecd2771be928977bebda9d10ff1973b07f4f1171a754c5c048d51da` |
| can_unlock_trace.log | `1bb9a81dc1ba02fc26358343cdbd9ec5` | `8b15463588a814b1544059a50799a20c9affddb2ccece5a4a5edf13a6c7b12ba` |
| field_service_extract.txt | `4a51b02405c9ae252146ef54233f903f` | `7cb738ad91bd90f323254b11d079aa916dd21338a2b74d4034fd7dbc6674a19e` |
| decode_card.png | `de16d42b4a1f3b6df1ce0c0ce6c516c0` | `89aa3d3e8123b0caf763ce7b080a29a147797fab7046cc6ba332c21db3e2874c` |
| keyless_pcb.png | `258129772e3b75c495f25f9fa93d38b8` | `e5917ac2aa17725565525117667bb64b9d1d7af9b8597c857d164a171b72b51e` |

校验命令：

```bash
md5sum    attachments/attachments/* attachments/attachments/maintenance_photos/*
sha256sum attachments/attachments/* attachments/attachments/maintenance_photos/*
```

---

## 结论

```
GEELY{CAN_c5007c61406904bf_f65dc5131e39daea}
```
