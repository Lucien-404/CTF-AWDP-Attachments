# Sentinel-2 压力网关 —— WriteUp

```
GEELY{SENTINEL_0aeaa5b8100366fe_3bbe8c612a7d9d6f}
```

附件（解压 `attachments.zip` 后得到 `attachments/attachments/`）：

| 文件 | 内容 |
|---|---|
| `evidence/tape_reader_card.png` | 磁带读取规范：FSK 调制参数 + 帧结构 + CRC 参数 |
| `evidence/tape_reader.wav` | 老磁带音频，载有 `ROT`、`MASK` |
| `evidence/update_rule.png` | 状态推进算法 + CAN payload 结构定义 |
| `evidence/segment_trace.log` | 96 帧 CAN 日志（混有拒绝帧） |
| `photos/gauge_panel.png` | 8 个旋转开关表盘 G0–G7 → `MULT` |
| `photos/sbox_ring.png` | 16 色替换环 + 颜色图例 → `SBOX` |

本题所有脚本都不需要手工猜参数，全部可自动化复现，脚本见文末 **§6 复现方式**（也可直接跑 `solve/solve_all.py`）。

---

## 1. 先读题目给定的两份规范

**`tape_reader_card.png`（磁带规范）**

```
TAPE READER CARD / REVISION 4
Mono FSK, 48 kHz, 16-bit PCM.
Mark bit 1 = 1800 Hz
Space bit 0 =  900 Hz
Bit period = 45 ms
Bit order  = MSB first

Frame:
  sync16 = A5 C3
  rot8   = rotation amount
  mask32 = final mask
  crc16  = X.25/FSC over all prior bytes

CRC-16/CCITT-FALSE, polynomial 0x1021,
initial value 0xFFFF, final XOR 0xFFFF, no reflection.
Ignore trailing silence and low-level noise.
```

**`update_rule.png`（状态推进算法）**

```
Accepted pressure frames have status byte 0x5A.
The final byte is XOR of all previous bytes.
Only accepted frames advance the 32-bit state.

STATE update, unsigned 32-bit:
  X = PREVIOUS xor COUNTER
  X = X * MULT
  X = rotate_left(X, ROT)
  X = X xor MASK
  X = substitute_nibbles(X, SBOX)
  STATE = X

Payload: counter(2 BE), state(4 BE), status(1), xor(1)

MULT comes from G0..G7 on the rotary bank photo.
MASK and ROT are in the tape-reader audio stream.
SBOX is clockwise from the notch on the ring photo.
```

于是任务被拆成 4 件事：音频 → `ROT/MASK`；表盘 → `MULT`；色环 → `SBOX`；日志 → 过滤有效帧、验证、预测下一帧。

---

## 2. 磁带音频 → ROT / MASK

45 ms × 48 kHz = **2160 采样/bit**，逐 bit 用 Goertzel 比较 1800 Hz 与 900 Hz 的能量判决 1/0；
掐掉首尾静音后在 bit 流里搜同步头 `A5 C3 = 1010010111000011`，再按 MSB-first 组字节。

**`step1_tape_rot_mask.py`**

```python
# -*- coding: utf-8 -*-
# 步骤1：磁带音频 FSK 解码 -> ROT / MASK / CRC 校验
import wave, numpy as np, re

WAV = r"..\attachments\attachments\evidence\tape_reader.wav"
w = wave.open(WAV, 'rb')
SR = w.getframerate()                                   # 48000
x = np.frombuffer(w.readframes(w.getnframes()), dtype='<i2').astype(np.float64)

BP = int(0.045 * SR)                                    # 45ms = 2160 采样/bit

def goertzel(seg, f):
    n = np.arange(len(seg))
    return abs(np.dot(seg, np.exp(-2j * np.pi * f * n / SR)))

# 只用有效信号段（掐掉尾部静音）
seg_len = SR // 200
rms = np.array([np.sqrt((x[i:i+seg_len] ** 2).mean()) for i in range(0, len(x) - seg_len, seg_len)])
idx = np.where(rms > 0.05 * rms.max())[0]
start, end = idx[0] * seg_len, (idx[-1] + 1) * seg_len

bits = ''.join('1' if goertzel(x[i:i+BP], 1800) > goertzel(x[i:i+BP], 900) else '0'
               for i in range(start, end - BP + 1, BP))
print("bit 流长度:", len(bits))

# 在 bit 流里找同步头 A5 C3 = 10100101 11000011
sync = '1010010111000011'
p = bits.find(sync)
bits = bits[p:]
nbyte = len(bits) // 8
data = bytes(int(bits[i*8:i*8+8], 2) for i in range(nbyte))
print("原始字节:", data.hex().upper())

# 解析帧: sync16 | rot8 | mask32 | crc16
rot = data[2]
mask = int.from_bytes(data[3:7], 'big')
crc_recv = int.from_bytes(data[7:9], 'big')

def crc16_ccitt_false(bs, init=0xFFFF, poly=0x1021, xorout=0xFFFF):
    crc = init
    for b in bs:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc ^ xorout

crc_calc = crc16_ccitt_false(data[:7])
print(f"sync = {data[:2].hex().upper()}")
print(f"ROT  = 0x{rot:02X} ({rot})")
print(f"MASK = 0x{mask:08X}")
print(f"CRC  接收=0x{crc_recv:04X}  计算=0x{crc_calc:04X}  -> {'OK' if crc_recv==crc_calc else 'FAIL'}")
```

输出：

```
bit 流长度: 72
原始字节: A5C30B3D6F8A153A44
sync = A5C3
ROT  = 0x0B (11)
MASK = 0x3D6F8A15
CRC  接收=0x3A44  计算=0x3A44  -> OK
```

CRC-16/CCITT-FALSE 自校验通过，说明 FSK 判决（阈值、位序、位周期）完全正确，于是：

```
ROT  = 0x0B = 11
MASK = 0x3D6F8A15
```

---

## 3. 旋转开关板照片 → MULT

表盘上没有数字，只有刻度：检测到**一圈 16 个刻度、间隔 22.5°**，所以“指针落在第几个刻度”就是 0–15 的读数。
处理流程：黑色像素连通域里筛出 8 个圆环（外接框约 95×95）→ 代数法最小二乘拟合圆心（迭代剔除刻度像素）→
对每个表盘的红色指针像素做“离圆心距离平方加权”的方向统计，得到指针角度。

**`step2_gauge_mult.py`**

```python
# -*- coding: utf-8 -*-
# 步骤2：旋转开关板照片 -> 8 个表盘指针读数 -> MULT
import numpy as np, math
from PIL import Image
from scipy import ndimage

IMG = r"..\attachments\attachments\photos\gauge_panel.png"
a = np.array(Image.open(IMG).convert('RGB')).astype(int)
r, g, b = a[:, :, 0], a[:, :, 1], a[:, :, 2]
dark = (r < 90) & (g < 90) & (b < 90)
red  = (r > 150) & (g < 100) & (b < 100)

# 1) 用连通域找出 8 个表盘圆环（约 95x95 的外接框）
lab, n = ndimage.label(dark)
rings = []
for i in range(1, n + 1):
    ys, xs = np.where(lab == i)
    w_, h_ = xs.max() - xs.min(), ys.max() - ys.min()
    if 70 < w_ < 120 and 70 < h_ < 120 and len(ys) > 400:
        rings.append((xs.mean(), ys.mean(), xs, ys))
rings.sort(key=lambda t: t[0])
print("检测到表盘数:", len(rings))

def fit_circle(xs, ys, iters=6):
    xs, ys = xs.astype(float), ys.astype(float)
    for _ in range(iters):
        A = np.c_[2 * xs, 2 * ys, np.ones(len(xs))]
        sol, *_ = np.linalg.lstsq(A, xs ** 2 + ys ** 2, rcond=None)
        cx, cy, c = sol
        R = math.sqrt(c + cx * cx + cy * cy)
        d = np.sqrt((xs - cx) ** 2 + (ys - cy) ** 2)
        keep = (d > R * 0.85) & (d < R * 1.12)
        xs, ys = xs[keep], ys[keep]
    return cx, cy, R

# 2) 拟合圆心 + 求红色指针方向（指针像素对圆心方向做加权 PCA）
vals = []
for (mx, my, xs, ys) in rings:
    cx, cy, R = fit_circle(xs, ys)
    win = red[int(cy) - int(R) - 8:int(cy) + int(R) + 8, int(cx) - int(R) - 8:int(cx) + int(R) + 8]
    py, px = np.where(win)
    py = py + int(cy) - int(R) - 8.0
    px = px + int(cx) - int(R) - 8.0
    vx, vy = px - cx, cy - py                       # 数学坐标(逆时针为正, 0=正东)
    d = np.sqrt(vx ** 2 + vy ** 2)
    wgt = d ** 2                                    # 越靠针尖权重越大
    ang = math.degrees(math.atan2((wgt * vy).sum(), (wgt * vx).sum())) % 360
    # 刻度一圈 16 格, 每格 22.5°; 0 在正上方(90°), 顺时针递增
    v = round((90 - ang) / 22.5) % 16
    vals.append(v)
    print(f"center=({cx:6.1f},{cy:6.1f}) R={R:5.1f}  指针角={ang:7.2f}°  -> 读数 {v:X}")

MULT = 0
for v in vals:
    MULT = (MULT << 4) | v                          # G0 为最高半字节
print("MULT = 0x%08X" % MULT)
```

输出：

```
检测到表盘数: 8
center=( 130.2, 300.3) R= 46.8  指针角= 292.45°  -> 读数 7
center=( 255.2, 300.3) R= 46.8  指针角= 113.94°  -> 读数 F
center=( 380.2, 300.3) R= 46.8  指针角=   0.58°  -> 读数 4
center=( 505.2, 300.3) R= 46.8  指针角= 222.87°  -> 读数 A
center=( 630.2, 300.3) R= 46.8  指针角=  68.55°  -> 读数 1
center=( 755.2, 300.3) R= 46.8  指针角=  47.13°  -> 读数 2
center=( 880.2, 300.3) R= 46.8  指针角= 179.44°  -> 读数 C
center=(1005.2, 300.3) R= 46.8  指针角= 244.90°  -> 读数 9
MULT = 0x7F4A12C9
```

得到 `MULT = 0x7F4A12C9`（G0 为最高半字节，与图片说明 *left-to-right, high to low nibble* 一致）。

> **关于“0 刻度在哪”**：表盘上唯一的方向标志是下方那个 “15” 量程标注，无法直接判定 0 刻度方位；
> 上式的 `round((90 - ang) / 22.5)` 假设 **0 在正上方、顺时针递增**。
> 这个假设不是猜的：§5 的脚本会枚举 16 种零点方位，**只有 0°=正上方这一种能让日志 71/71 条状态转移成立**，
> 其余 15 种全部 0/71。也就是说 `MULT` 被“照片读数 + 日志数据”双向锁定。

---

## 4. 替换环照片 → SBOX

环上 16 个色点从缺口（正上方）顺时针每 22.5° 一个，位置编号 `0..F` 就是 S 盒的**输入**半字节；
底部图例给出 “颜色 → 数字”（第一行最左侧黑色方块没有标号，即 `0`），是 S 盒的**输出**半字节。

要点：
1. 只有 12 个点是彩色的（红/白/黑/浅灰 4 点饱和度不足），所以先只用彩色点拟合环心与半径，再按几何角度取 16 个位置的颜色——黑白灰点也能取到；
2. 图例数字是**黑色文字压在色块上**，取样必须用**众数**（出现次数最多的颜色）而不是均值，否则“白块”会被平均成灰色而与浅灰混淆；
3. 用 16×16 颜色距离矩阵 + 匈牙利算法做**全局一一匹配**，天然满足“S 盒是双射”的约束。

**`step3_ring_sbox.py`**

```python
# -*- coding: utf-8 -*-
# 步骤3：替换环照片 -> SBOX（环上位置 = 输入半字节, 图例颜色 -> 输出半字节）
import numpy as np, math
from PIL import Image
from scipy import ndimage
from scipy.optimize import linear_sum_assignment

IMG = r"..\attachments\attachments\photos\sbox_ring.png"
a = np.array(Image.open(IMG).convert('RGB')).astype(int)
sat = (a.max(2) - a.min(2)) > 40          # 有彩色像素（黑白灰点不满足，靠几何位置补齐）

lab, n = ndimage.label(sat)
dots, swatch = [], []
for i in range(1, n + 1):
    ys, xs = np.where(lab == i)
    if len(ys) < 500:
        continue
    (dots if ys.mean() < 790 else swatch).append((xs.mean(), ys.mean()))
print("环上彩色圆点 %d 个（另有红/白/黑/灰 4 个非彩色点靠几何位置取色）" % len(dots))

# 用彩色圆点拟合环心/半径
xs = np.array([p[0] for p in dots]); ys = np.array([p[1] for p in dots])
A = np.c_[2 * xs, 2 * ys, np.ones(len(xs))]
cx, cy, c = np.linalg.lstsq(A, xs ** 2 + ys ** 2, rcond=None)[0]
R = math.sqrt(c + cx * cx + cy * cy)
print(f"环心=({cx:.1f},{cy:.1f})  半径={R:.1f}")

def mode_color(x, y, r=12):
    """取小方框内出现次数最多的颜色（图例里的数字是黑字，必须避开，故用众数而不是均值）"""
    reg = a[int(y) - r:int(y) + r, int(x) - r:int(x) + r].reshape(-1, 3)
    v, cnt = np.unique(reg, axis=0, return_counts=True)
    return v[cnt.argmax()]

# 环上位置: 从缺口(正上方)顺时针, 每 22.5° 一个, 共 16 个
pos_rgb = []
for k in range(16):
    ang = 90 - 22.5 * k
    px, py = cx + R * math.cos(math.radians(ang)), cy - R * math.sin(math.radians(ang))
    pos_rgb.append(mode_color(px, py))

# 图例: 第1行 x=70,175,...,805 对应 [0(黑),1,2,3,4,5,6,7]; 第2行 同理对应 [8,9,A,B,C,D,E,F]
legend = []
for j, x0 in enumerate([70, 175, 280, 385, 490, 595, 700, 805]):
    legend.append((j,     mode_color(x0 + 24, 814)))
    legend.append((j + 8, mode_color(x0 + 24, 859)))

for k in range(16):
    print(f"  位置 {k:X}: RGB=({pos_rgb[k][0]:3d},{pos_rgb[k][1]:3d},{pos_rgb[k][2]:3d})")

# 16x16 颜色距离 + 匈牙利算法做全局最优一一匹配
D = np.array([[np.linalg.norm(p - legend[j][1]) for j in range(16)] for p in pos_rgb])
row, col = linear_sum_assignment(D)
sbox = [0] * 16
for i, j in zip(row, col):
    sbox[i] = legend[j][0]
print("SBOX = [" + ", ".join("%X" % v for v in sbox) + "]")
print("双射校验:", sorted(sbox) == list(range(16)))
```

输出：

```
环上彩色圆点 12 个（另有红/白/黑/灰 4 个非彩色点靠几何位置取色）
环心=(449.7,469.6)  半径=300.2
  位置 0: RGB=(224, 64,192)
  位置 1: RGB=( 28,138, 58)
  位置 2: RGB=( 32, 96,208)
  位置 3: RGB=(216,216,216)
  位置 4: RGB=(255,255,255)
  位置 5: RGB=(  0,  0,  0)
  位置 6: RGB=(200,117, 51)
  位置 7: RGB=(  0,183,208)
  位置 8: RGB=(255,136,  0)
  位置 9: RGB=(128,128,  0)
  位置 A: RGB=(  0, 32,128)
  位置 B: RGB=(141,141,141)
  位置 C: RGB=(255,230,128)
  位置 D: RGB=(138, 78,208)
  位置 E: RGB=(123, 74, 18)
  位置 F: RGB=(221, 34, 34)
SBOX = [C, 5, 6, B, 9, 0, A, D, 3, E, F, 8, 4, 7, 1, 2]
双射校验: True
```

即：

```
SBOX[i] : 0→C  1→5  2→6  3→B  4→9  5→0  6→A  7→D  8→3  9→E  A→F  B→8  C→4  D→7  E→1  F→2
```

---

## 5. 日志：过滤有效帧 → 验证参数 → 预测下一帧 → flag

日志每行形如 `(1791000000.000000) can2 18EF4A10#0FF00D3AC9B05BEA`，把 `#` 后的 16 位 hex 拆成
`counter(2,BE) | state(4,BE) | status(1) | xor(1)`：

- 96 帧的**末字节异或校验 96/96 全部通过**（说明日志本身合法，只是混入了拒绝帧）；
- `status == 0x5A` 的是**有效帧，共 72 帧**，counter 从 `0x1000` 连续到 `0x1047`；
- 尾部第 73–95 帧 status 为 `44/91/37/A5/5B`，即**拒绝帧**：它们的 `state` 字段是随机噪声、counter 乱跳
  （`0x1081/0x10C7/0x1131/…`，同一 counter 还反复出现 1–3 次），**不推进状态**，只能当噪声丢掉；

接着实现状态机，并用“枚举 16 种表盘零点方位”的方式给 `MULT` 定标，然后预测下一帧：

**`step4_predict_flag.py`**

```python
# -*- coding: utf-8 -*-
# 步骤4：日志解析 -> 过滤有效帧 -> 用状态机验证参数 -> 预测下一帧 -> SHA-256 -> flag
import re, hashlib

LOG = r"..\attachments\attachments\evidence\segment_trace.log"

ROT  = 11
MASK = 0x3D6F8A15
SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
NEEDLE_ANGLES = [292.45, 113.94, 0.58, 222.87, 68.55, 47.13, 179.44, 244.90]  # 步骤2 输出
M = 0xFFFFFFFF

def rotl(x, r):
    return ((x << r) | (x >> (32 - r))) & M

def sub_nib(x):
    return sum(SBOX[(x >> (4 * i)) & 0xF] << (4 * i) for i in range(8))

def advance(prev_state, counter, mult):
    x = (prev_state ^ counter) & M
    x = (x * mult) & M
    x = rotl(x, ROT)
    x ^= MASK
    return sub_nib(x)

# ---- 1. 读日志: payload = counter(2,BE) | state(4,BE) | status(1) | xor(1) ----
frames = []
for line in open(LOG):
    line = line.strip()
    if not line:
        continue
    d = bytes.fromhex(re.search(r'#(\w{16})', line).group(1))
    chk = 0
    for b in d[:7]:
        chk ^= b
    frames.append((int.from_bytes(d[0:2], 'big'),
                   int.from_bytes(d[2:6], 'big'),
                   d[6], d[7], chk == d[7]))
valid = [(c, s) for c, s, st, xb, ok in frames if st == 0x5A]
print(f"总帧 {len(frames)}  末字节异或校验通过 {sum(f[4] for f in frames)}")
print(f"有效帧(status=0x5A) {len(valid)}  counter {valid[0][0]:04X} -> {valid[-1][0]:04X}")

# ---- 2. 表盘"0 刻度位置"定标：16 种角度偏移里只有一种能让日志 71/71 成立 ----
def mult_from_offset(off):
    v = 0
    for ang in NEEDLE_ANGLES:
        v = (v << 4) | (round((off * 22.5 - ang) / 22.5) % 16)
    return v

hits = []
for off in range(16):
    mt = mult_from_offset(off)
    if all(advance(valid[i][1], valid[i + 1][0], mt) == valid[i + 1][1] for i in range(len(valid) - 1)):
        hits.append((off, mt))
print("与日志完全一致的表盘零点假设:", [(f"{o*22.5:.1f}°", f"0x{m:08X}") for o, m in hits])

MULT = hits[0][1]
bad = sum(1 for i in range(len(valid) - 1)
          if advance(valid[i][1], valid[i + 1][0], MULT) != valid[i + 1][1])
print(f"参数: MULT=0x{MULT:08X}  ROT={ROT}  MASK=0x{MASK:08X}")
print(f"状态机验证: {len(valid)-1-bad}/{len(valid)-1} 条转移成立")

# ---- 3. 预测下一帧（锚定"最后一条有效帧"，忽略尾部拒绝帧） ----
last_c, last_s = valid[-1]
nc = last_c + 1
ns = advance(last_s, nc, MULT)
print(f"最后有效帧: counter={last_c:04X} state={last_s:08X}")
print(f"  中间值: A=p^c=0x{(last_s^nc)&M:08X}  A*MULT=0x{(last_s^nc)*MULT&M:08X}  "
      f"rotl=0x{rotl((last_s^nc)*MULT&M, ROT):08X}  ^MASK=0x{rotl((last_s^nc)*MULT&M, ROT)^MASK:08X}")

payload = bytes([nc >> 8, nc & 0xFF]) + ns.to_bytes(4, 'big') + bytes([0x5A])
xorb = 0
for b in payload:
    xorb ^= b
payload += bytes([xorb])
hexs = payload.hex().upper()
print(f"下一帧完整数据: {hexs}   (counter {nc:04X} | state {ns:08X} | 5A | {xorb:02X})")

# ---- 4. hash -> flag ----
h = hashlib.sha256(hexs.encode()).hexdigest()
print(f"SHA-256({hexs}) = {h}")
print(f"FLAG: GEELY{{SENTINEL_{h[:16]}_{h[-16:]}}}")
```

输出：

```
总帧 96  末字节异或校验通过 96
有效帧(status=0x5A) 72  counter 1000 -> 1047
与日志完全一致的表盘零点假设: [('90.0°', '0x7F4A12C9')]
参数: MULT=0x7F4A12C9  ROT=11  MASK=0x3D6F8A15
状态机验证: 71/71 条转移成立
最后有效帧: counter=1047 state=110F8EB8
  中间值: A=p^c=0x110F9EF0  A*MULT=0x7FD0AA70  rotl=0x855383FE  ^MASK=0xB83C09EB
下一帧完整数据: 104883B4CE185AE3   (counter 1048 | state 83B4CE18 | 5A | E3)
SHA-256(104883B4CE185AE3) = 0aeaa5b8100366fef201429711bdf033ae39ceef310153573bbe8c612a7d9d6f
FLAG: GEELY{SENTINEL_0aeaa5b8100366fe_3bbe8c612a7d9d6f}
```

**预测过程手算版**（下一帧 `counter = 0x1047 + 1 = 0x1048`）：

```
A  = 0x110F8EB8 ^ 0x1048 = 0x110F9EF0
X1 = A * 0x7F4A12C9 mod 2^32 = 0x7FD0AA70
X2 = rotl(X1, 11)            = 0x855383FE
X3 = X2 ^ 0x3D6F8A15         = 0xB83C09EB        <- 半字节 B,E,9,0,C,3,8,B
X4 = sub_nib(X3)             = 0x83B4CE18        <- 查表 B→8, E→1, 9→E, 0→C, C→4, 3→B, 8→3, B→8
xor = 10^48^83^B4^CE^18^5A   = 0xE3
```

=> 下一帧完整数据 **`104883B4CE185AE3`**（counter `1048` | state `83B4CE18` | status `5A` | xor `E3`）

题目要求 `GEELY{SENTINEL_<hash前16位>_<hash后16位>}`，对这份大写十六进制数据串取 **SHA-256**（64 位 hex，取前 16 位 + 后 16 位，正好构成 flag 格式）：

```
sha256("104883B4CE185AE3")
 = 0aeaa5b8100366fef201429711bdf033ae39ceef310153573bbe8c612a7d9d6f
```

### Flag

```
GEELY{SENTINEL_0aeaa5b8100366fe_3bbe8c612a7d9d6f}
```

---

## 6. 复现方式

目录结构（脚本按相对路径读取附件，`solve/` 与 `attachments/` 同级）：

```
Pressure Gate/
├── attachments.zip                # 题目附件（解压后得到下面的 attachments/attachments/）
├── attachments/attachments/{evidence,photos}/...
├── solve/
│   ├── solve_all.py               # 一键跑完步骤 1~4
│   ├── step1_tape_rot_mask.py     # 音频 FSK 解码 -> ROT/MASK
│   ├── step2_gauge_mult.py        # 表盘读数 -> MULT
│   ├── step3_ring_sbox.py         # 色环取色 -> SBOX
│   ├── step4_predict_flag.py      # 日志验证 + 预测下一帧 + SHA-256 -> flag
│   └── appendix_z3_verify.py      # 附录：z3 独立反解 MULT/SBOX 互证
└── WP-Sentinel-2-压力网关.md
```

依赖：`Python 3.8+`、`numpy`、`Pillow`、`scipy`（附录脚本另需 `z3-solver`）

```bash
pip install numpy pillow scipy z3-solver
cd "Pressure Gate/solve"
python solve_all.py            # 一键复现（依次执行 step1~step4）
python step4_predict_flag.py   # 或单独跑关键一步
python appendix_z3_verify.py   # 附录：仅凭日志反解参数
```

> 若把脚本放到别处，只需把各脚本开头的 `WAV` / `IMG` / `LOG` 路径改成实际路径即可。

---

## 7. 附录 A：只用日志做约束求解（与照片互证）

`MULT` 未知、`SBOX` 是 16 元置换、`ROT/MASK` 固定，把“有效帧状态转移”写成 SMT 约束交给 z3，
可以从**日志数据侧**独立反解出 `MULT` 与整个 `SBOX`（前 16 条有效帧就足够），与照片/色环的读数完全一致——
这一步既是交叉验证，也是当照片读数有歧义（例如“两个灰点”）时的兜底手段。

**`appendix_z3_verify.py`**

```python
# -*- coding: utf-8 -*-
# 附录：只用日志做约束求解，独立反解 MULT 与 SBOX，与照片/音频结果互证
import re, z3
from z3 import BitVec, BitVecVal, BitVecSort, Function, Solver, RotateLeft, Extract, Distinct

LOG = r"..\attachments\attachments\evidence\segment_trace.log"
ROT, MASK, R = 11, 0x3D6F8A15, 32

frames = []
for line in open(LOG):
    line = line.strip()
    if not line:
        continue
    d = bytes.fromhex(re.search(r'#(\w{16})', line).group(1))
    frames.append((int.from_bytes(d[0:2], 'big'), int.from_bytes(d[2:6], 'big'), d[6]))
valid = [(c, s) for c, s, st in frames if st == 0x5A][:16]   # 取前 16 条有效帧足够

MULT = BitVec('MULT', 32)
Sbox = Function('Sbox', BitVecSort(4), BitVecSort(4))
s = Solver()
s.add(Distinct([Sbox(BitVecVal(k, 4)) for k in range(16)]))  # SBOX 必须是 4bit 双射

for i in range(len(valid) - 1):
    c0, s0 = valid[i]
    c1, s1 = valid[i + 1]
    Z = RotateLeft(BitVecVal((s0 ^ c1) & 0xFFFFFFFF, 32) * MULT, ROT) ^ BitVecVal(MASK, 32)
    for k in range(8):
        s.add(Sbox(Extract(4 * k + 3, 4 * k, Z)) == Extract(4 * k + 3, 4 * k, BitVecVal(s1, 32)))

print("check:", s.check())
m = s.model()
print("z3 反解 MULT = 0x%08X" % m[MULT].as_long())
print("z3 反解 SBOX = [" + ", ".join("%X" % m.eval(Sbox(BitVecVal(k, 4))).as_long() for k in range(16)) + "]")
```

输出：

```
check: sat
z3 反解 MULT = 0x7F4A12C9
z3 反解 SBOX = [C, 5, 6, B, 9, 0, A, D, 3, E, F, 8, 4, 7, 1, 2]
```

## 8. 附录 B：一键复现脚本

**`solve_all.py`**

```python
# -*- coding: utf-8 -*-
# 一键复现：依次执行步骤 1~4
import runpy, os, sys
os.chdir(os.path.dirname(os.path.abspath(__file__)))
for f in ("step1_tape_rot_mask.py", "step2_gauge_mult.py", "step3_ring_sbox.py", "step4_predict_flag.py"):
    print("\n" + "=" * 20 + " " + f + " " + "=" * 20)
    runpy.run_path(f, run_name="__main__")
```

运行结果（末尾）：

```
==================== step4_predict_flag.py ====================
总帧 96  末字节异或校验通过 96
有效帧(status=0x5A) 72  counter 1000 -> 1047
与日志完全一致的表盘零点假设: [('90.0°', '0x7F4A12C9')]
参数: MULT=0x7F4A12C9  ROT=11  MASK=0x3D6F8A15
状态机验证: 71/71 条转移成立
最后有效帧: counter=1047 state=110F8EB8
  中间值: A=p^c=0x110F9EF0  A*MULT=0x7FD0AA70  rotl=0x855383FE  ^MASK=0xB83C09EB
下一帧完整数据: 104883B4CE185AE3   (counter 1048 | state 83B4CE18 | 5A | E3)
SHA-256(104883B4CE185AE3) = 0aeaa5b8100366fef201429711bdf033ae39ceef310153573bbe8c612a7d9d6f
FLAG: GEELY{SENTINEL_0aeaa5b8100366fe_3bbe8c612a7d9d6f}
```

---

## 9. 踩坑与经验

1. **音频帧先验 CRC 再往下走。** 磁带帧自带 X.25/FSC 校验，解出 `A5C30B3D6F8A15` 后算得 `0x3A44` 与帧内一致，
   一次性确认了 FSK 判决（阈值、MSB/LSB、2160 采样/bit）全部正确，避免带着错误参数去“凑”日志。
2. **表盘必须先定标“0 刻度在哪”。** 表盘上没有数字，只有 16 个 22.5° 的刻度；若想当然按“0 在右边”读，
   会把大半 nibble 读错，日志变成 0/71。正确做法：枚举 16 种零点方位，只有“0 在正上方、顺时针”能让 71/71 成立；
   再用 z3 从日志侧独立反解 `MULT`，两条路径互相印证，比“看图片猜”可靠得多。
3. **图例取样要用众数，不能用均值。** 图例的数字是黑字压在色块上，均值会把白块拉成灰、与浅灰撞车；
   再加上 16×16 距离矩阵 + 匈牙利算法做全局一一匹配，才稳定得到双射 S 盒。
4. **“两个灰点”这种同色歧义用置换约束消掉。** S 盒必须是 `0..F` 的双射，颜色最近邻若有歧义，置换约束能唯一定解。
5. **拒绝帧是纯噪声，但必须显式过滤。** 尾部 23 帧 status 非 `0x5A`，`state` 字段随机、counter 乱跳；
   只有 `status==0x5A` 的 72 帧构成连续的 counter 链（`0x1000→0x1047`），这一条干净的链本身就是算法正确性的证明。
6. **“下一帧”要锚定在最后一条*有效*帧。** 若顺手拿日志最后一行（拒绝帧）当基准，算出的 state 完全不同——
   这是本题最大的诱导点。
7. **hash 的输入与算法要靠“flag 结构”反推。** 题目只说 “hash”，但格式 `<前16位>_<后16位>` 提示取 SHA-256 的前 16 位 + 后 16 位，
   输入是日志同款式样的**大写十六进制串** `104883B4CE185AE3`；换成 MD5 或原始字节会得到完全不同的 flag。

---

## 10. 答案汇总

| 项目 | 值 |
|---|---|
| ROT | `11`（0x0B） |
| MASK | `0x3D6F8A15` |
| MULT | `0x7F4A12C9` |
| SBOX | `[C,5,6,B,9,0,A,D,3,E,F,8,4,7,1,2]` |
| 有效帧 | 72 帧（status=0x5A，counter `0x1000`–`0x1047`） |
| 最后有效帧 | counter `0x1047`，state `0x110F8EB8` |
| 下一帧完整数据 | `104883B4CE185AE3` |
| SHA-256 | `0aeaa5b8100366fef201429711bdf033ae39ceef310153573bbe8c612a7d9d6f` |
| **FLAG** | **`GEELY{SENTINEL_0aeaa5b8100366fe_3bbe8c612a7d9d6f}`** |
