# Chromatic Custody — WriteUp

> **分类**：Misc / Forensics · 双板几何配准 + 颜色异或 + HMAC-SHA256
> **Flag**：`GEELY{80e4bf16c0cd763f6c9bf3220af0fe6b37729e7ff7042b54f131ba41f747f69b}`
> **密钥**：`2b9811754604d2c8c40268e21e903777`
> **难度**：中等偏上（算法都不难，坑在「后板整体旋转 4.24°，不配准会读错一半以上」和「记录串怎么序列化」）
> **依赖**：`python3` + `numpy` + `pillow`（本文末脚本可直接复制运行，不需要 cv2 / 不需要其它脚本）

---

## 0. 题目

```
一批旧车 custody 记录在迁移中被拆成两块受损印刷板。任何一块单独保存都不能恢复签名密钥。
审计人员只留下两张扫描板、一张配准卡和一个证据封套。

你需要先完成两块板的几何配准，再按颜色规则还原 16 字节密钥，最后计算 custody 记录的认证摘要。
```

附件是 6 个 PNG：证据封套、配准卡、两张受损扫描板（数据藏在这里）、两张同尺寸纯色空板。

**证据封套的内容（本题全部规格都在这里）**：

```
CUSTODY ENVELOPE / CHROMATIC OVERLAY

operator: overlay-custody
vehicle: LGXFE4SB8N2077653
epoch: 1790412800

plate rule: red xor cyan
secret width: 16 bytes
authentication: HMAC-SHA256
```

**配准卡的内容**：

```
REGISTRATION JIG / THREE FIDUCIALS
   1（左上）  2（右上）  3（左下）   三枚红十字
Place cyan marks over matching red marks
```

---

## 1. 附件特征：板上到底有什么（这是解题的地基）

两张扫描板都是 **1600 × 1300** RGB。两张 `*_blank.png` 逐像素统计只有 **1 种颜色**
（`front_blank` = `(251,247,239)`，`rear_blank` = `(248,251,253)`），是空板，不含数据；
所有 PNG 都没有 tEXt 文本块、IEND 之后也没有附加数据 —— **数据只在两张 plate 的像素里**。

每张 plate 上有三类要素：

| 要素 | front_plate（红） | rear_plate（青） |
| --- | --- | --- |
| 点阵 **实心** 格点 | 红 `(205,30,30)` 实心圆 | 青 `(10,145,190)` 实心圆（带深青描边 `(8,90,125)`） |
| 点阵 **空心** 格点 | 米色细环 `(175,160,145)` | 淡蓝细环 `(150,185,205)` |
| **基准点 fiducial** ×3 | 红实心圆 + 黑环 + `F` 字形标记 | 青实心圆 + 黑环 |
| 随机散点 ≈600 个 | 半径随机、位置随机 | 同左 |

关键量化结论：

1. **中央点阵是 8 列 × 16 行 = 128 个格点**，正好等于 16 字节 × 8 bit。
   * 前板栅距（轴对齐）：原点 `(630,240)`，`u=(54,0)`，`v=(0,54)`
   * 后板栅距：原点 `(667,256)`，`u=(54,4)`，`v=(-4,54)`
     → `u` 与 `v` 正交且模长都是 54.15，即**后板整体旋转 `atan2(4,54) = 4.24°`**。
     这是本题第一个大坑（见 §6 踩坑记录）。
2. **散点是纯“污损”干扰**：做过模 8/10/12/13/16/20/27 的栅格检验，分布均匀；
   实测点阵 128 个格点的取色比例只有 `0.0` 和 `1.0` 两个值 —— 说明散点**刻意避开了点阵内部**，
   不需要任何去噪/形态学处理。
3. 只有两张 plate 同时在场才能凑齐 128 bit；单张板只能给出“自己那一半”，
   这正对应题目里“任何一块单独保存都不能恢复签名密钥”。

---

## 2. 步骤 1：几何配准（本题的核心步骤）

### 2.1 提取三枚基准点

基准点是「黑环 + 圆心」的环形连通域（bbox 27×27、面积 569），用连通域质心直接得到：

| | F1 | F2 | F3 |
| --- | --- | --- | --- |
| `front_plate` | (150, 150) | (1420, 180) | (210, 1120) |
| `rear_plate` | (198, 126) | (1460, 256) | (182, 1101) |
| `registration_jig`（红十字，仅示意） | (90.2, 120.2) | (660.2, 150.2) | (140.2, 420.2) |

### 2.2 三点最小二乘相似变换 + 穷举验证

对三点做 SVD 求「前板 → 后板」的最优相似变换（允许反射），然后把**前板整套 8×16 点阵**
映射到后板坐标系，测量与**后板实际点阵**的偏差（单位：格）：

基准点顺序穷举 `3! = 6` 种 × {有/无反射} = 12 种，结果：

| 基准点对应（前 → 后） | 旋转角 | 点阵残差 max |
| --- | --- | --- |
| **1↔1, 2↔2, 3↔3，无反射** | **+4.443°** | **0.068 格 ✅** |
| 1↔1, 3↔2, 2↔3 | −175.798° | 0.328 格 |
| 3↔1, 2↔2, 1↔3 | +4.393° | 0.428 格 |
| 其余排列（含全部反射解） | — | ≥ 0.48 格（反射解恰好 0.500 格） |

判据：**残差 0.068 格远小于半格（0.5 格）**，说明两板上的点阵是**同一套物理格点**；
而反射解残差恰好 0.5 格（完美错半格），是所有解里最差的，一眼排除。

结论：

```
尺度 = 1.00017      旋转 = +4.443°      front(i,j) ↔ rear(i,j)   （无平移、无翻转）
```

### 2.3 双路互证（必做）

把前板格点用该变换映射到后板坐标系，在**原始后板图**上重新取位，结果与“直接按后板格点取位”
**逐位一致（128/128）**；反过来，若不配准、直接用前板格坐标去读后板，会 **读错 72/128 位**
（≈ 一半以上的位错），得到的“密钥”完全是另一串随机字节。

> 配准卡不能用来求变换：它三个红十字的三角形与两板 fiducial 三角形**不相似**
> （边长比 3.20 / 2.23 / 2.60 ≠ 常数），它只是提示“青板基准点要盖到红十字上”。
> 真正定标必须靠**两板各自的三枚 fiducial 之间的相似关系**。

---

## 3. 步骤 2：red xor cyan → 16 字节密钥

### 3.1 取位规范

本题题面没写清点阵怎么读。但同一出题风格的姊妹题 **Ghost Fleet** 里，`archive_policy.png`
把这份点阵规范白纸黑字写出（它是同族题共用的编码规范），本题沿用同一套：

```
read the dot matrix in 16 rows x 8 columns      # 16 行 × 8 列（不是 8 行 × 16 列）
row 0 is byte 0 ; row 15 is byte 15             # 每一“行”是一个字节
left column is bit 7 ; right column is bit 0    # 每行最左列是 MSB
filled dot = 1 ; hollow dot = 0                 # 实心 = 1，空心 = 0
```

所以一张板 = `16 行 × 8 列 = 128 bit = 16 字节`。

### 3.2 读数与异或

* 前板实心 **58** 个格点，后板实心 **71** 个格点（合计 128 位）
* 取色比例只有 `0.0 / 1.0`，**零歧义**

`plate rule: red xor cyan` 逐位异或（`#`=1，`.`=0）：

```
..#.#.##   -> 2b           ##.#..#.   -> d2           .##.#...   -> 68
#..##...      98           ##..#...      c8           ###...#.      e2
...#...#      11           ##...#..      c4           ...####.      1e
.###.#.#      75           ......#.      02           #..#....      90
.#...##.      46           .##.#...      68           ..##.###      37
.....#..      04           ###...#.      e2           .###.###      77
```

```
KEY = 2b9811754604d2c8c40268e21e903777        (16 bytes)
```

---

## 4. 步骤 3：custody 记录的认证摘要

封套给了两个规格，正好对应最后一步的两半：

```
secret width: 16 bytes        -> HMAC 的 KEY = 上一步那 16 个原始字节
authentication: HMAC-SHA256   -> CODE = HMAC-SHA256(KEY, custody 记录)
```

**custody 记录** = 封套里三个记录字段的**值**，按出现顺序用 `|` 连接
（不带字段名标签、不带行尾换行、不带引号）：

```
record = "overlay-custody|LGXFE4SB8N2077653|1790412800"
```

计算：

```
CODE = HMAC-SHA256(key = 2b9811754604d2c8c40268e21e903777,
                   msg = "overlay-custody|LGXFE4SB8N2077653|1790412800")
     = 80e4bf16c0cd763f6c9bf3220af0fe6b37729e7ff7042b54f131ba41f747f69b
```

flag 形态为 `GEELY{<CODE>}`：

```
GEELY{80e4bf16c0cd763f6c9bf3220af0fe6b37729e7ff7042b54f131ba41f747f69b}
```

---

## 5. 完整复现脚本（自包含，复制即跑）

把下面代码存成 `solve.py`，放在题目根目录（或 `work/` 子目录，脚本会自动向上找附件）后执行
`python solve.py`。仅需 `numpy` + `pillow`。

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chromatic Custody -- 完整复现脚本 (仅需 numpy + pillow, 无需 cv2)

流程:
  0) 自动定位附件目录, 读入两张扫描板
  1) 检测 3 枚 fiducial -> 三点相似变换(前板->后板) -> 穷举 12 种对应验证配准唯一性
  2) 按 16 行 x 8 列 读点阵 (row=byte, 左列=bit7, 实心=1)
     - 前板: 红(205,30,30) 实心 / 米色(175,160,145) 空心
     - 后板: 青(10,145,190) 实心 / 淡蓝(150,185,205) 空心, 整体旋转 4.24 度
     - 双路互证: 直接在各自坐标系取位 vs 把前板格点映射到后板坐标系取位, 必须逐位一致
  3) red xor cyan -> 16 字节密钥
  4) HMAC-SHA256(key, "operator|vehicle|epoch") -> CODE -> flag
"""
import hashlib
import hmac
import itertools
import os
import sys

import numpy as np
from PIL import Image

# ---------------------------------------------------------------- 附件定位
def find_base(start="."):
    start = os.path.abspath(start)
    roots = [start]
    for _ in range(4):                      # 逐级向上找(脚本可能放在 work/ 子目录)
        roots.append(os.path.dirname(roots[-1]))
    for r in roots:
        for c in (os.path.join(r, "attachments", "attachments"),
                  os.path.join(r, "attachments"), r):
            if os.path.isfile(os.path.join(c, "plates", "front_plate.png")):
                return c
    for root, _dirs, files in os.walk(start):
        if "front_plate.png" in files and os.path.basename(root) == "plates":
            return os.path.dirname(root)
    raise SystemExit("[-] 找不到 plates/front_plate.png, 请在题目目录下运行")


BASE = find_base(os.path.dirname(os.path.abspath(__file__)) or ".")

# ---------------------------------------------------------------- 已知几何参数
# 三枚 fiducial 圆心 (黑环连通域质心), 顺序 1/2/3
FID_F = np.array([(150.0, 150.0), (1420.0, 180.0), (210.0, 1120.0)])   # front_plate
FID_R = np.array([(198.0, 126.0), (1460.0, 256.0), (182.0, 1101.0)])   # rear_plate
FID_J = np.array([(90.2, 120.2), (660.2, 150.2), (140.2, 420.2)])      # registration_jig(仅示意)

# 点阵: 原点 + 两个栅距向量 (后板 u/v 非轴对齐 => 整体旋转 4.24deg)
O_F, U_F, V_F = np.array([630.0, 240.0]), np.array([54.0, 0.0]), np.array([0.0, 54.0])
O_R, U_R, V_R = np.array([667.0, 256.0]), np.array([54.0, 4.0]), np.array([-4.0, 54.0])

FILL_F, EMPTY_F = (205, 30, 30), (175, 160, 145)
FILL_R, EMPTY_R = (10, 145, 190), (150, 185, 205)

ROWS, COLS = 16, 8          # 16 行 x 8 列 = 128 bit = 16 byte
TOL, RAD = 70, 7            # 取色容差 / 采样圆盘半径


# ---------------------------------------------------------------- 工具
def load(name):
    return np.array(Image.open(os.path.join(BASE, name)).convert("RGB")).astype(int)


def disk_mask(rad=RAD):
    yy, xx = np.mgrid[-rad:rad + 1, -rad:rad + 1]
    return (xx ** 2 + yy ** 2) <= rad * rad


DISK = disk_mask()


def fill_fraction(img, mask, cx, cy):
    """在 (cx,cy) 处取 rad 半径圆盘内属于 mask 的像素比例"""
    x, y = int(round(cx)), int(round(cy))
    sub = mask[y - RAD:y + RAD + 1, x - RAD:x + RAD + 1]
    if sub.shape != DISK.shape:
        raise ValueError("采样点越界: (%.1f, %.1f)" % (cx, cy))
    return sub[DISK].mean()


def read_plate(img, origin, u, v, fill_rgb):
    """按 16x8 点阵读数 -> (16,8) 位矩阵 + 取色比例矩阵"""
    mask = (np.abs(img - np.array(fill_rgb)).sum(axis=2) < TOL)
    bits = np.zeros((ROWS, COLS), int)
    frac = np.zeros((ROWS, COLS))
    for i in range(COLS):
        for j in range(ROWS):
            p = origin + i * u + j * v
            f = fill_fraction(img, mask, p[0], p[1])
            frac[j, i] = f
            bits[j, i] = 1 if f > 0.5 else 0
    return bits, frac


def similarity(src, dst, reflect=False):
    """三点最小二乘相似变换 src->dst, 返回 (scale, Rot, src_center, dst_center)"""
    ca, cb = src.mean(0), dst.mean(0)
    X, Y = src - ca, dst - cb
    U, S, Vt = np.linalg.svd(X.T @ Y)
    d = np.sign(np.linalg.det(Vt.T @ U.T))
    if reflect:
        d = -d
    Rot = Vt.T @ np.diag([1.0, d]) @ U.T
    scale = S.sum() / (X ** 2).sum()
    return scale, Rot, ca, cb


def apply_sim(t, p):
    scale, Rot, ca, cb = t
    return (scale * Rot @ (np.asarray(p, float) - ca)) + cb


# ---------------------------------------------------------------- 步骤 1: 配准
def step1_registration():
    print("=" * 74)
    print("[1] 几何配准 (三点相似变换, 穷举 3! x {有/无反射} = 12 种)")
    print("=" * 74)
    Mm = np.array([U_R, V_R]).T
    Mmi = np.linalg.inv(Mm)

    results = []
    for reflect in (False, True):
        for perm in itertools.permutations(range(3)):
            t = similarity(np.array([FID_F[i] for i in perm]), FID_R, reflect)
            res = []
            for i in range(COLS):
                for j in range(ROWS):
                    p = apply_sim(t, O_F + i * U_F + j * V_F)   # 前板格点 -> 后板坐标系
                    ij = Mmi @ (p - O_R)
                    res.append(np.abs(ij - np.round(ij)).max())  # 与后板格点的偏离(单位:格)
            results.append((max(res), np.mean(res), reflect, perm, t))
    results.sort(key=lambda r: r[0])

    print("%-46s %-12s %-10s" % ("基准点对应(前->后) / 是否反射", "旋转角", "点阵残差max"))
    for err_max, err_mean, reflect, perm, t in results[:3]:
        rot = np.degrees(np.arctan2(t[1][1, 0], t[1][0, 0]))
        print("%-46s %+9.3f deg %8.3f 格" %
              ("%s%s" % (perm, "  反射" if reflect else "  无反射"), rot, err_max))
    print("... (其余组合残差 >= %.2f 格)" % results[3][0])

    err_max, err_mean, reflect, perm, t = results[0]
    assert not reflect and perm == (0, 1, 2), "最优配准不是 identity, 请人工复核"
    assert err_max < 0.25, "配准残差过大"
    print("[*] 唯一最优: 1<->1, 2<->2, 3<->3 无反射, 尺度=%.5f, 残差 max=%.3f 格 (<<0.5 格)"
          % (t[0], err_max))
    print("[*] => 两板是同一套物理格点, front(i,j) <-> rear(i,j), 无平移无翻转")
    return t


def step1_verify(t, bits_r):
    """双路互证: 把前板格点用配准变换映射到后板坐标系, 在原始后板图上重新取位"""
    rear = load("plates/rear_plate.png")
    mask = (np.abs(rear - np.array(FILL_R)).sum(axis=2) < TOL)
    bits2 = np.zeros((ROWS, COLS), int)
    for i in range(COLS):
        for j in range(ROWS):
            p = apply_sim(t, O_F + i * U_F + j * V_F)
            bits2[j, i] = 1 if fill_fraction(rear, mask, p[0], p[1]) > 0.5 else 0
    assert (bits2 == bits_r).all(), "配准后重取样与直接读数不一致!"
    print("[*] 双路互证通过: 直接按后板格点取位 == 由前板格点配准映射后取位 (128/128)")
    # 不配准的对照
    bad = 0
    for i in range(COLS):
        for j in range(ROWS):
            p = O_F + i * U_F + j * V_F     # 错: 用前板坐标系直接读后板
            bad += (1 if fill_fraction(rear, mask, p[0], p[1]) > 0.5 else 0) != bits_r[j, i]
    print("[*] 对照: 若不配准直接用前板格坐标读后板 -> %d/128 位读错" % bad)


# ---------------------------------------------------------------- 步骤 2/3/4
def step2_key(t):
    print()
    print("=" * 74)
    print("[2] 读点阵 (16 行 x 8 列, row=byte, 左列=bit7, 实心=1) 与 red xor cyan")
    print("=" * 74)
    front, rear = load("plates/front_plate.png"), load("plates/rear_plate.png")
    b_f, f_f = read_plate(front, O_F, U_F, V_F, FILL_F)
    b_r, f_r = read_plate(rear, O_R, U_R, V_R, FILL_R)
    step1_verify(t, b_r)

    allfrac = np.round(np.r_[f_f.ravel(), f_r.ravel()], 1)
    vals = sorted(set(allfrac.tolist()))
    print("[*] 256 个格点取色比例取值集合 = %s  (完全双峰, 零歧义)" % vals)
    assert set(vals) <= {0.0, 1.0}
    print("[*] 实心点: 前板 %d 个, 后板 %d 个 (共 128 位)" % (b_f.sum(), b_r.sum()))

    x = b_f ^ b_r
    print("[*] 位矩阵 (red xor cyan, #=1 .=0):")
    for j in range(ROWS):
        print("      " + "".join(".#"[b] for b in x[j]))
    key = bytes(int("".join(str(b) for b in x[j]), 2) for j in range(ROWS))
    print("[+] KEY (16 bytes) = %s" % key.hex())
    return key


def step3_flag(key):
    print()
    print("=" * 74)
    print("[3] custody 记录的认证摘要 (HMAC-SHA256)")
    print("=" * 74)
    operator, vehicle, epoch = "overlay-custody", "LGXFE4SB8N2077653", "1790412800"
    record = "%s|%s|%s" % (operator, vehicle, epoch)   # 字段值用 '|' 拼接, 无标签无换行
    code = hmac.new(key, record.encode(), hashlib.sha256).hexdigest()
    print("[*] secret width = 16 bytes  -> HMAC KEY = 原始 16 字节")
    print("[*] record = %r" % record)
    print("[*] CODE   = %s" % code)
    flag = "GEELY{%s}" % code
    print()
    print("[+] FLAG: %s" % flag)
    return flag


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8") if hasattr(sys.stdout, "reconfigure") else None
    t = step1_registration()
    key = step2_key(t)
    step3_flag(key)

```

运行输出（关键行）：

```
[1] 几何配准 (三点相似变换, 穷举 3! x {有/无反射} = 12 种)
(0, 1, 2)  无反射    +4.443 deg    0.068 格
(0, 2, 1)  无反射  -175.798 deg    0.328 格
(2, 1, 0)  无反射    +4.393 deg    0.428 格
... (其余组合残差 >= 0.48 格)
[*] 唯一最优: 1<->1, 2<->2, 3<->3 无反射, 尺度=1.00017, 残差 max=0.068 格 (<<0.5 格)
[*] => 两板是同一套物理格点, front(i,j) <-> rear(i,j), 无平移无翻转

[2] 读点阵 (16 行 x 8 列, row=byte, 左列=bit7, 实心=1) 与 red xor cyan
[*] 双路互证通过: 直接按后板格点取位 == 由前板格点配准映射后取位 (128/128)
[*] 对照: 若不配准直接用前板格坐标读后板 -> 72/128 位读错
[*] 256 个格点取色比例取值集合 = [0.0, 1.0]  (完全双峰, 零歧义)
[*] 实心点: 前板 58 个, 后板 71 个 (共 128 位)
[+] KEY (16 bytes) = 2b9811754604d2c8c40268e21e903777

[3] custody 记录的认证摘要 (HMAC-SHA256)
[*] record = 'overlay-custody|LGXFE4SB8N2077653|1790412800'
[*] CODE   = 80e4bf16c0cd763f6c9bf3220af0fe6b37729e7ff7042b54f131ba41f747f69b

[+] FLAG: GEELY{80e4bf16c0cd763f6c9bf3220af0fe6b37729e7ff7042b54f131ba41f747f69b}
```

**三行速通版**（如果你只想验证最后一步，密钥已知时）：

```python
import hashlib, hmac
key = bytes.fromhex("2b9811754604d2c8c40268e21e903777")
msg = b"overlay-custody|LGXFE4SB8N2077653|1790412800"
print("GEELY{%s}" % hmac.new(key, msg, hashlib.sha256).hexdigest())
```

---

## 6. 踩坑记录（复现时最容易翻车的点）

1. **点阵是 16 行 × 8 列，不是 8 行 × 16 列** ★★★
   字节按**行**、bit 按**列**（左列为 bit7）。如果按列当字节读，会得到另一串“看起来也很像密钥”
   的随机值，而且看不出错 —— 必须靠同族题目的显式规范来锚定。
2. **后板整体旋转 4.24°，必须先配准** ★★★
   直接用前板的格坐标去读后板 → 128 位里错 72 位，密钥两半全错。
   正确姿势：三点相似变换（前 fiducial → 后 fiducial），并用「映射后点阵与后板点阵的残差」
   做判据；残差 0.068 格 ≪ 0.5 格才说明配准对了。
3. **别把镜像/错位对应关系当成解** ★★
   反射解残差恰好 0.500 格（完美错半格，是最差解）；`1↔1,3↔2,2↔3` 之类也只有 0.33~0.43 格。
   排一下残差表就能一眼锁定唯一解 `1↔1, 2↔2, 3↔3 / 无反射`。
4. **配准卡不是用来求变换的**：它三叉三角形与两板 fiducial 三角形不相似，
   只是视觉提示；定标必须用两板各自的三枚 fiducial。
5. **散点不要花时间清理**：随机位置/随机半径，且避开点阵内部，原图直接取色就是 0.0/1.0 双峰；
   `*_blank.png` 是单色空板，别去找数据。
6. **记录串的序列化是本题唯一的“猜点”** ★★★
   本题 `题目内容.txt` 里**没有 flag 模板行**（同族其它题都有，例如
   `flag格式GEELY{CAN_<sha256前16位>_<sha256后16位>}`），封套也没写记录串怎么拼。
   实测答案是**三字段值用 `|` 拼接、无标签、无换行换行符**。
   经验：同族题的 hash/HMAC 输入优先试「管道符拼接的纯值」，其次才是逐行文本（带 `\n`）、
   JSON、`key=value` 形式；`KEY` 用 16 字节**原始字节**，不要用 hex 字符串。
   排查时把候选全列出来逐个试（本题实际试到第 5 个序列化候选才命中，最终确认的就是 §4 里那个 record）。

---

## 7. 🚩 Flag

```
GEELY{80e4bf16c0cd763f6c9bf3220af0fe6b37729e7ff7042b54f131ba41f747f69b}
```
