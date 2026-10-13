# 帆软FineReportReportSeverSqlite注入导致远程代码执行漏洞

- **系统**：致远OA　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`"Powered by 帆软"`
- **请求**：`GET /webroot/decision/view/ReportServer?test=sssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss`
- **关键头**：`content-type: application/x-www-form-urlencoded`　`x-forwarded-for: xxxx`
- **预期**：200　|　—