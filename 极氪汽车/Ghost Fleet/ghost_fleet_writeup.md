# Ghost Fleet 题解 / Writeup

## 题目概述

一次旧车联网平台迁移后，部分隐藏车队记录没有进入正式资产清单。审计侧只恢复出：

- 5 张冷存档恢复碎片；
- 1 份残缺底盘标签；
- 1 份托管记录；
- 1 条代理租户提示；
- 以及 `archive_policy.png` 中给出的校验规则。

最终要求提交：

```text
GEELY{<sha256_hex>}
```

题目补充提示：

```text
ascii("ops_shadow|xxxxxx|xxxxxx")
|| bytes.fromhex("xxxxxxxxxxxxxxxx")
```

也就是说，需要恢复三个 ASCII 字段以及一个 16 字节密钥，并将两部分直接拼接后计算 SHA-256。

---

## 一、分析 `archive_policy.png`

`archive_policy.png` 给出了恢复碎片的合法性判定规则：

1. 左上校准点必须为 **实心**；
2. 右上校准点必须为 **空心**；
3. `PARITY` 点必须等于所有数据点的异或结果。

据此检查 5 张恢复碎片后，可以筛出真正有效的记录。

最终有效碎片为：

```text
A17
C09
F31
```

而：

```text
D12
E88
```

不满足校准点或奇偶校验条件，因此属于诱饵数据。

---

## 二、恢复 3 组有效碎片数据

每张碎片中的数据区按：

```text
16 行 × 8 列
```

进行读取。

位序规则为：

- 左侧为 bit7；
- 右侧为 bit0；
- 实心点记为 1；
- 空心点记为 0。

恢复得到：

### Fragment A17

```text
GF-2026-A17
c8f0bc5b58b68f7d07735f9213d9827e
```

### Fragment C09

```text
GF-2026-C09
8f56f8196920de2496a8e121e3aa7bea
```

### Fragment F31

```text
GF-2026-F31
72dd9be0d0c616242c79bb824c9a135d
```

---

## 三、恢复 16 字节密钥

将三组有效数据逐字节异或：

```text
c8f0bc5b58b68f7d07735f9213d9827e
8f56f8196920de2496a8e121e3aa7bea
72dd9be0d0c616242c79bb824c9a135d
--------------------------------
357bdfa2e150477dbda20531bce9eac9
```

因此最终恢复出的 16 字节密钥为：

```text
357bdfa2e150477dbda20531bce9eac9
```

注意这里是 **16 字节原始数据**，不是 32 字符十六进制文本。

在 Python 中应使用：

```python
bytes.fromhex("357bdfa2e150477dbda20531bce9eac9")
```

---

## 四、恢复底盘标签

残缺底盘标签上的字符从左至右拼接为：

```text
LSVA24 RZ7M 1098 423
```

去掉空格后得到：

```text
LSVA24RZ7M1098423
```

该字符串长度为 17，符合 VIN / 底盘编号长度特征。

因此第二个 ASCII 字段为：

```text
LSVA24RZ7M1098423
```

---

## 五、恢复代理租户字段

代理租户提示为：

```text
shadow operations
```

结合题目明确给出的目标格式：

```text
ascii("ops_shadow|xxxxxx|xxxxxx")
```

可知其规范化形式应为：

```text
ops_shadow
```

因此第一个 ASCII 字段为：

```text
ops_shadow
```

---

## 六、恢复托管记录字段

托管记录中提取到时间值：

```text
1789600000
```

因此 ASCII 部分完整内容为：

```text
ops_shadow|LSVA24RZ7M1098423|1789600000
```

---

## 七、构造最终 SHA-256 输入

题目要求：

```text
ascii("ops_shadow|xxxxxx|xxxxxx")
|| bytes.fromhex("xxxxxxxxxxxxxxxx")
```

所以最终输入不是：

```text
ops_shadow|LSVA24RZ7M1098423|1789600000|357bdfa2...
```

也不是把密钥十六进制字符串作为 ASCII 拼接。

正确形式为：

```python
ascii_part = b"ops_shadow|LSVA24RZ7M1098423|1789600000"

key = bytes.fromhex(
    "357bdfa2e150477dbda20531bce9eac9"
)

data = ascii_part + key
```

然后计算：

```python
sha256(data)
```

---

## 八、复现脚本

```python
import hashlib

ascii_part = b"ops_shadow|LSVA24RZ7M1098423|1789600000"

key = bytes.fromhex(
    "357bdfa2e150477dbda20531bce9eac9"
)

data = ascii_part + key

digest = hashlib.sha256(data).hexdigest()

print(digest)
print(f"GEELY{{{digest}}}")
```

输出：

```text
d40a971673369ea262ca89bfea2da80f3ae02cd4738505fdde5a4f12f921a425
```

---

## 九、最终 Flag

```text
GEELY{d40a971673369ea262ca89bfea2da80f3ae02cd4738505fdde5a4f12f921a425}
```

---

## 解题思路总结

本题整体链路为：

```text
archive_policy.png
        ↓
校验 5 张恢复碎片
        ↓
筛出 A17 / C09 / F31
        ↓
提取 3 组 16 字节数据
        ↓
逐字节 XOR
        ↓
恢复密钥
357bdfa2e150477dbda20531bce9eac9
        ↓
恢复 chassis / tenant / escrow 字段
        ↓
ops_shadow|LSVA24RZ7M1098423|1789600000
        ↓
ASCII 字节串 || 16 字节密钥
        ↓
SHA-256
        ↓
GEELY{...}
```
